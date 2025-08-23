import os
import time
import hashlib
import stat
import threading
import logging
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from app import db
from models import ScanResult, ThreatDetail, ThreatAlert

class SafeFileHandler(FileSystemEventHandler):
    """Safe file system event handler for monitoring"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        super().__init__()
    
    def on_modified(self, event):
        if not event.is_directory:
            self.scanner.analyze_file_safely(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            self.scanner.analyze_file_safely(event.src_path)

class SystemScanner:
    def __init__(self):
        self.quarantine_dir = os.path.expanduser('~/.ransomware_quarantine')
        self.backup_dir = os.path.expanduser('~/.ransomware_backup')
        self.ensure_directories()
        self.observer = None
        self.monitoring = False
        
        # Safe file extensions to scan
        self.scannable_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.scr', '.com', '.pif',
            '.js', '.vbs', '.jar', '.py', '.ps1', '.sh', '.bin'
        }
        
        # Suspicious file patterns
        self.suspicious_patterns = [
            'readme.txt', 'how_to_decrypt', 'ransom', 'decrypt',
            'restore_files', 'recovery', '_crypt', '_locked'
        ]
        
        # Entropy thresholds for encrypted files
        self.entropy_threshold = 7.5
    
    def ensure_directories(self):
        """Ensure quarantine and backup directories exist"""
        for directory in [self.quarantine_dir, self.backup_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory, mode=0o700)  # Restricted permissions
    
    def safe_file_check(self, file_path):
        """Safely check if file exists and is accessible"""
        try:
            return os.path.exists(file_path) and os.access(file_path, os.R_OK)
        except (OSError, PermissionError):
            return False
    
    def get_file_metadata(self, file_path):
        """Safely get file metadata without modifying the file"""
        try:
            if not self.safe_file_check(file_path):
                return None
            
            file_stat = os.stat(file_path)
            return {
                'size': file_stat.st_size,
                'modified': datetime.fromtimestamp(file_stat.st_mtime),
                'created': datetime.fromtimestamp(file_stat.st_ctime),
                'permissions': stat.filemode(file_stat.st_mode),
                'is_executable': bool(file_stat.st_mode & stat.S_IEXEC)
            }
        except (OSError, PermissionError) as e:
            logging.warning(f"Could not get metadata for {file_path}: {e}")
            return None
    
    def calculate_file_hash(self, file_path):
        """Safely calculate file hash without modifying the file"""
        try:
            if not self.safe_file_check(file_path):
                return None
            
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except (OSError, PermissionError, IOError) as e:
            logging.warning(f"Could not hash file {file_path}: {e}")
            return None
    
    def calculate_entropy(self, file_path, sample_size=1024):
        """Calculate file entropy to detect encryption"""
        try:
            if not self.safe_file_check(file_path):
                return 0.0
            
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
            
            if len(data) == 0:
                return 0.0
            
            # Calculate entropy
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count == 0:
                    continue
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
        except (OSError, PermissionError, IOError) as e:
            logging.warning(f"Could not calculate entropy for {file_path}: {e}")
            return 0.0
    
    def analyze_file_safely(self, file_path):
        """Safely analyze a file for ransomware indicators"""
        try:
            if not self.safe_file_check(file_path):
                return None
            
            # Get file metadata
            metadata = self.get_file_metadata(file_path)
            if not metadata:
                return None
            
            # Calculate hash
            file_hash = self.calculate_file_hash(file_path)
            
            # Calculate entropy
            entropy = self.calculate_entropy(file_path)
            
            # Check for suspicious patterns
            file_name = os.path.basename(file_path).lower()
            is_suspicious_name = any(pattern in file_name for pattern in self.suspicious_patterns)
            
            # Check if extension suggests executable
            file_ext = Path(file_path).suffix.lower()
            is_executable_type = file_ext in self.scannable_extensions
            
            # Determine threat level
            threat_level = 'low'
            risk_factors = []
            
            if entropy > self.entropy_threshold:
                threat_level = 'medium'
                risk_factors.append('High entropy (possibly encrypted)')
            
            if is_suspicious_name:
                threat_level = 'high'
                risk_factors.append('Suspicious filename pattern')
            
            if is_executable_type and entropy > 7.0:
                threat_level = 'high'
                risk_factors.append('Suspicious executable with high entropy')
            
            if metadata['size'] == 0:
                risk_factors.append('Zero-byte file')
            
            return {
                'file_path': file_path,
                'file_hash': file_hash,
                'file_size': metadata['size'],
                'entropy': entropy,
                'threat_level': threat_level,
                'risk_factors': risk_factors,
                'metadata': metadata
            }
            
        except Exception as e:
            logging.error(f"File analysis error for {file_path}: {e}")
            return None
    
    def quick_scan(self, target_path, scan_id):
        """Perform a quick scan of critical directories"""
        try:
            scan_result = ScanResult.query.get(scan_id)
            start_time = time.time()
            
            # Critical directories to scan quickly
            critical_dirs = [
                os.path.expanduser('~/Desktop'),
                os.path.expanduser('~/Documents'),
                os.path.expanduser('~/Downloads'),
                '/tmp',
                '/var/tmp'
            ]
            
            files_scanned = 0
            threats_found = 0
            
            for directory in critical_dirs:
                if os.path.exists(directory) and os.access(directory, os.R_OK):
                    for root, dirs, files in os.walk(directory):
                        for file in files[:100]:  # Limit for quick scan
                            file_path = os.path.join(root, file)
                            analysis = self.analyze_file_safely(file_path)
                            
                            if analysis:
                                files_scanned += 1
                                
                                if analysis['threat_level'] in ['medium', 'high', 'critical']:
                                    threats_found += 1
                                    self.create_threat_record(scan_id, analysis)
            
            # Update scan result
            end_time = time.time()
            scan_result.status = 'completed'
            scan_result.files_scanned = files_scanned
            scan_result.threats_found = threats_found
            scan_result.scan_duration = end_time - start_time
            scan_result.completed_at = datetime.utcnow()
            db.session.commit()
            
            logging.info(f"Quick scan completed: {files_scanned} files, {threats_found} threats")
            return {'files_scanned': files_scanned, 'threats_found': threats_found}
            
        except Exception as e:
            logging.error(f"Quick scan error: {e}")
            if scan_result:
                scan_result.status = 'failed'
                db.session.commit()
            return None
    
    def full_scan(self, target_path, scan_id):
        """Perform a full system scan"""
        try:
            scan_result = ScanResult.query.get(scan_id)
            start_time = time.time()
            
            files_scanned = 0
            threats_found = 0
            
            # Scan the specified path recursively
            if os.path.exists(target_path) and os.access(target_path, os.R_OK):
                for root, dirs, files in os.walk(target_path):
                    # Skip system directories and hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['proc', 'sys', 'dev']]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        analysis = self.analyze_file_safely(file_path)
                        
                        if analysis:
                            files_scanned += 1
                            
                            if analysis['threat_level'] in ['medium', 'high', 'critical']:
                                threats_found += 1
                                self.create_threat_record(scan_id, analysis)
                        
                        # Update progress periodically
                        if files_scanned % 1000 == 0:
                            scan_result.files_scanned = files_scanned
                            scan_result.threats_found = threats_found
                            db.session.commit()
            
            # Update final scan result
            end_time = time.time()
            scan_result.status = 'completed'
            scan_result.files_scanned = files_scanned
            scan_result.threats_found = threats_found
            scan_result.scan_duration = end_time - start_time
            scan_result.completed_at = datetime.utcnow()
            db.session.commit()
            
            logging.info(f"Full scan completed: {files_scanned} files, {threats_found} threats")
            return {'files_scanned': files_scanned, 'threats_found': threats_found}
            
        except Exception as e:
            logging.error(f"Full scan error: {e}")
            if scan_result:
                scan_result.status = 'failed'
                db.session.commit()
            return None
    
    def create_threat_record(self, scan_id, analysis):
        """Create a threat record in the database"""
        try:
            threat = ThreatDetail(
                scan_result_id=scan_id,
                file_path=analysis['file_path'],
                threat_type='ransomware_indicator',
                threat_level=analysis['threat_level'],
                confidence_score=0.8,  # Base confidence
                file_hash=analysis['file_hash'],
                file_size=analysis['file_size']
            )
            
            db.session.add(threat)
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Error creating threat record: {e}")
    
    def quarantine_file(self, file_path):
        """Safely quarantine a suspicious file"""
        try:
            if not self.safe_file_check(file_path):
                raise ValueError("File not accessible")
            
            # Create backup first
            backup_path = self.backup_file(file_path)
            
            # Generate unique quarantine filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            file_hash = self.calculate_file_hash(file_path)[:8]
            quarantine_filename = f"{timestamp}_{file_hash}_{os.path.basename(file_path)}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Move file to quarantine (copy then remove original)
            import shutil
            shutil.copy2(file_path, quarantine_path)
            os.remove(file_path)
            
            # Set restricted permissions on quarantined file
            os.chmod(quarantine_path, 0o600)
            
            logging.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return quarantine_path
            
        except Exception as e:
            logging.error(f"Quarantine error for {file_path}: {e}")
            raise
    
    def backup_file(self, file_path):
        """Create a backup of the file before quarantine"""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"{timestamp}_{os.path.basename(file_path)}"
            backup_path = os.path.join(self.backup_dir, backup_filename)
            
            import shutil
            shutil.copy2(file_path, backup_path)
            
            logging.info(f"File backed up: {file_path} -> {backup_path}")
            return backup_path
            
        except Exception as e:
            logging.error(f"Backup error for {file_path}: {e}")
            raise
    
    def start_monitoring(self, path='/'):
        """Start real-time file system monitoring"""
        try:
            if self.monitoring:
                return
            
            self.observer = Observer()
            event_handler = SafeFileHandler(self)
            self.observer.schedule(event_handler, path, recursive=True)
            self.observer.start()
            self.monitoring = True
            
            logging.info(f"Started monitoring: {path}")
            
        except Exception as e:
            logging.error(f"Monitoring start error: {e}")
    
    def stop_monitoring(self):
        """Stop real-time file system monitoring"""
        try:
            if self.observer and self.monitoring:
                self.observer.stop()
                self.observer.join()
                self.monitoring = False
                logging.info("Stopped monitoring")
                
        except Exception as e:
            logging.error(f"Monitoring stop error: {e}")
