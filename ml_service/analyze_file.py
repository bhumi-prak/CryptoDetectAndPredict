#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import math
import time
from pathlib import Path
import threading
from typing import Dict, List, Tuple, Optional

class SafeFileAnalyzer:
    """Safe file analyzer that only reads files without modification"""
    
    def __init__(self):
        self.ransomware_signatures = [
            b'\x4d\x5a',  # PE header
            b'\x7f\x45\x4c\x46',  # ELF header
            b'LOCKY',  # Locky ransomware
            b'WANNACRY',  # WannaCry
            b'RYUK',  # Ryuk
            b'MAZE',  # Maze
        ]
        
        self.suspicious_extensions = {
            '.encrypted', '.locked', '.crypto', '.crypt', '.crypted',
            '.WANNACRY', '.WNCRY', '.WCRY', '.locky', '.zepto',
            '.thor', '.aesir', '.odin', '.shit', '.fuck',
            '.xxx', '.micro', '.dharma', '.wallet', '.onion'
        }
        
        self.crypto_indicators = [
            'bitcoin', 'BTC', 'cryptocurrency', 'decrypt',
            'ransom', 'payment', 'tor browser', 'onion'
        ]

    def safe_read_file(self, file_path: str, max_size: int = 1024*1024) -> Optional[bytes]:
        """Safely read file content with size limits"""
        try:
            file_size = os.path.getsize(file_path)
            if file_size > max_size:
                # Only read first part of large files
                with open(file_path, 'rb') as f:
                    return f.read(max_size)
            else:
                with open(file_path, 'rb') as f:
                    return f.read()
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def check_file_signature(self, data: bytes) -> bool:
        """Check for known ransomware signatures"""
        for signature in self.ransomware_signatures:
            if signature in data:
                return True
        return False

    def check_suspicious_strings(self, data: bytes) -> int:
        """Count suspicious crypto-related strings"""
        try:
            text = data.decode('utf-8', errors='ignore').lower()
            count = 0
            for indicator in self.crypto_indicators:
                count += text.count(indicator.lower())
            return count
        except:
            return 0

    def analyze_single_file(self, file_path: str) -> Dict:
        """Safely analyze a single file"""
        try:
            # Get file info safely
            stat = os.stat(file_path)
            file_size = stat.st_size
            
            # Check extension
            file_ext = Path(file_path).suffix.lower()
            is_suspicious_ext = file_ext in self.suspicious_extensions
            
            # Read file content safely
            data = self.safe_read_file(file_path)
            if data is None:
                return {
                    'file_path': file_path,
                    'error': 'Cannot read file safely',
                    'threat_level': 'UNKNOWN'
                }
            
            # Calculate features
            entropy = self.calculate_entropy(data)
            has_signature = self.check_file_signature(data)
            suspicious_strings = self.check_suspicious_strings(data)
            
            # Calculate hash for identification
            file_hash = hashlib.sha256(data).hexdigest()
            
            # Determine threat level
            threat_score = 0
            if entropy > 7.5:  # High entropy indicates encryption
                threat_score += 3
            elif entropy > 6.5:
                threat_score += 2
            elif entropy > 5.5:
                threat_score += 1
                
            if has_signature:
                threat_score += 4
                
            if suspicious_strings > 0:
                threat_score += suspicious_strings
                
            if is_suspicious_ext:
                threat_score += 3
            
            # Classify threat level
            if threat_score >= 6:
                threat_level = 'CRITICAL'
            elif threat_score >= 4:
                threat_level = 'HIGH'
            elif threat_score >= 2:
                threat_level = 'MEDIUM'
            else:
                threat_level = 'LOW'
            
            return {
                'file_path': file_path,
                'file_size': file_size,
                'entropy': entropy,
                'threat_level': threat_level,
                'threat_score': threat_score,
                'has_signature': has_signature,
                'suspicious_strings': suspicious_strings,
                'file_hash': file_hash,
                'confidence': min(0.95, (threat_score / 10) + 0.3),
                'is_encrypted': entropy > 7.0,
                'features': {
                    'entropy': entropy,
                    'file_size': file_size,
                    'suspicious_extension': is_suspicious_ext,
                    'signature_match': has_signature,
                    'crypto_indicators': suspicious_strings
                }
            }
            
        except Exception as e:
            return {
                'file_path': file_path,
                'error': str(e),
                'threat_level': 'ERROR'
            }

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python analyze_file.py <filename>"}))
        return
    
    filename = sys.argv[1]
    analyzer = SafeFileAnalyzer()
    result = analyzer.analyze_single_file(filename)
    
    print(json.dumps(result))

if __name__ == "__main__":
    main()