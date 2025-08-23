#!/usr/bin/env python3
import os
import sys
import json
import threading
import time
from pathlib import Path
from typing import Dict, List, Generator
from analyze_file import SafeFileAnalyzer

class SafeSystemScanner:
    """Safe system-wide scanner that only reads files"""
    
    def __init__(self):
        self.analyzer = SafeFileAnalyzer()
        self.scan_stats = {
            'total_files': 0,
            'scanned_files': 0,
            'threats_found': 0,
            'errors': 0,
            'start_time': 0,
            'scan_active': False
        }
        self.scan_results = []
        
        # Safe directories to scan
        self.scan_directories = self.get_safe_scan_directories()
        
        # Skip system and protected directories
        self.skip_directories = {
            'System32', 'Windows', 'WinSxS', 'Recovery',
            'ProgramData', '$Recycle.Bin', 'pagefile.sys',
            'hiberfil.sys', 'swapfile.sys', 'proc', 'sys',
            'dev', 'tmp', 'var/log', '.git', 'node_modules'
        }
        
        # File types to prioritize
        self.priority_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.scr', '.pif',
            '.com', '.jar', '.zip', '.rar', '.7z', '.pdf',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.mp4', '.avi'
        }

    def get_safe_scan_directories(self) -> List[str]:
        """Get safe directories to scan based on OS"""
        safe_dirs = []
        
        if os.name == 'nt':  # Windows
            # Scan user directories and common locations
            user_dir = os.path.expanduser('~')
            safe_dirs.extend([
                user_dir,
                os.path.join(user_dir, 'Desktop'),
                os.path.join(user_dir, 'Documents'),
                os.path.join(user_dir, 'Downloads'),
                os.path.join(user_dir, 'Pictures'),
                'C:\\Users\\Public',
            ])
        else:  # Linux/Unix
            user_dir = os.path.expanduser('~')
            safe_dirs.extend([
                user_dir,
                '/home',
                '/opt',
                '/usr/local'
            ])
        
        # Filter to existing directories
        return [d for d in safe_dirs if os.path.exists(d)]

    def should_skip_directory(self, dir_path: str) -> bool:
        """Check if directory should be skipped for safety"""
        dir_name = os.path.basename(dir_path)
        return any(skip in dir_path for skip in self.skip_directories)

    def should_scan_file(self, file_path: str) -> bool:
        """Check if file should be scanned"""
        try:
            # Skip if file is too large (>100MB)
            if os.path.getsize(file_path) > 100 * 1024 * 1024:
                return False
            
            # Skip system files and hidden files
            if os.path.basename(file_path).startswith('.'):
                return False
                
            # Prioritize certain file types
            file_ext = Path(file_path).suffix.lower()
            return file_ext in self.priority_extensions or file_ext == ''
            
        except (OSError, PermissionError):
            return False

    def safe_walk_directory(self, directory: str) -> Generator[str, None, None]:
        """Safely walk directory tree"""
        try:
            for root, dirs, files in os.walk(directory):
                # Skip protected directories
                if self.should_skip_directory(root):
                    dirs.clear()  # Don't recurse into subdirectories
                    continue
                
                # Remove protected subdirectories from scan
                dirs[:] = [d for d in dirs if not self.should_skip_directory(os.path.join(root, d))]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.should_scan_file(file_path):
                        yield file_path
                        
        except (PermissionError, OSError) as e:
            self.scan_stats['errors'] += 1

    def count_files_to_scan(self) -> int:
        """Count total files that will be scanned"""
        total = 0
        for directory in self.scan_directories:
            try:
                for _ in self.safe_walk_directory(directory):
                    total += 1
            except:
                pass
        return total

    def scan_file_safe(self, file_path: str) -> Dict:
        """Safely scan a single file"""
        try:
            result = self.analyzer.analyze_single_file(file_path)
            self.scan_stats['scanned_files'] += 1
            
            if result.get('threat_level') in ['HIGH', 'CRITICAL']:
                self.scan_stats['threats_found'] += 1
                self.scan_results.append(result)
            
            return result
            
        except Exception as e:
            self.scan_stats['errors'] += 1
            return {
                'file_path': file_path,
                'error': f'Scan error: {str(e)}',
                'threat_level': 'ERROR'
            }

    def quick_scan(self) -> Dict:
        """Perform quick scan of high-priority locations"""
        self.scan_stats['scan_active'] = True
        self.scan_stats['start_time'] = time.time()
        self.scan_results.clear()
        
        # Quick scan locations
        quick_locations = [
            os.path.expanduser('~/Desktop'),
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Documents')
        ]
        
        quick_locations = [loc for loc in quick_locations if os.path.exists(loc)]
        
        total_files = 0
        for location in quick_locations:
            for _ in self.safe_walk_directory(location):
                total_files += 1
        
        self.scan_stats['total_files'] = total_files
        
        for location in quick_locations:
            for file_path in self.safe_walk_directory(location):
                if not self.scan_stats['scan_active']:  # Allow stopping scan
                    break
                self.scan_file_safe(file_path)
        
        self.scan_stats['scan_active'] = False
        return self.get_scan_summary()

    def full_system_scan(self) -> Dict:
        """Perform comprehensive system scan"""
        self.scan_stats['scan_active'] = True
        self.scan_stats['start_time'] = time.time()
        self.scan_results.clear()
        
        # Count total files first
        print("Counting files to scan...", file=sys.stderr)
        self.scan_stats['total_files'] = self.count_files_to_scan()
        
        # Scan all safe directories
        for directory in self.scan_directories:
            if not self.scan_stats['scan_active']:
                break
                
            for file_path in self.safe_walk_directory(directory):
                if not self.scan_stats['scan_active']:
                    break
                self.scan_file_safe(file_path)
                
                # Report progress
                if self.scan_stats['scanned_files'] % 100 == 0:
                    progress = (self.scan_stats['scanned_files'] / max(1, self.scan_stats['total_files'])) * 100
                    print(f"Progress: {progress:.1f}%", file=sys.stderr)
        
        self.scan_stats['scan_active'] = False
        return self.get_scan_summary()

    def get_scan_summary(self) -> Dict:
        """Get current scan summary"""
        elapsed_time = time.time() - self.scan_stats['start_time'] if self.scan_stats['start_time'] > 0 else 0
        
        return {
            'scan_complete': not self.scan_stats['scan_active'],
            'total_files': self.scan_stats['total_files'],
            'scanned_files': self.scan_stats['scanned_files'],
            'threats_found': self.scan_stats['threats_found'],
            'errors': self.scan_stats['errors'],
            'elapsed_time': elapsed_time,
            'threats': self.scan_results[-10:],  # Last 10 threats
            'scan_active': self.scan_stats['scan_active']
        }

    def stop_scan(self):
        """Safely stop the current scan"""
        self.scan_stats['scan_active'] = False

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python system_scanner.py <quick|full|status|stop>"}))
        return
    
    command = sys.argv[1].lower()
    scanner = SafeSystemScanner()
    
    if command == 'quick':
        result = scanner.quick_scan()
        print(json.dumps(result))
    elif command == 'full':
        result = scanner.full_system_scan()
        print(json.dumps(result))
    elif command == 'status':
        result = scanner.get_scan_summary()
        print(json.dumps(result))
    elif command == 'stop':
        scanner.stop_scan()
        print(json.dumps({"message": "Scan stopped safely"}))
    else:
        print(json.dumps({"error": "Invalid command. Use: quick, full, status, or stop"}))

if __name__ == "__main__":
    main()