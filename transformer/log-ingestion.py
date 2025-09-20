# real-log-ingestion.py  
# Real Apache/Nginx Log Ingestion from actual log files
# Automatically finds common log file locations and processes real logs

import os
import sys
import time
from datetime import datetime
from pathlib import Path
import re
from typing import Dict, List, Any, Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    print("⚠️ Install watchdog for real-time monitoring: pip install watchdog")
    WATCHDOG_AVAILABLE = False

try:
    from transformer_model import WebAttackTransformer
    TRANSFORMER_AVAILABLE = True
except ImportError:
    TRANSFORMER_AVAILABLE = False
    print("⚠️ Transformer model not available")

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealLogFinder:
    """
    Automatically finds Apache/Nginx log files on the system
    """
    
    def __init__(self):
        """Initialize log file finder"""
        self.common_log_paths = {
            'apache': [
                # Ubuntu/Debian Apache
                '/var/log/apache2/access.log',
                '/var/log/apache2/access_log',
                # CentOS/RHEL Apache
                '/var/log/httpd/access_log',
                '/etc/httpd/logs/access_log',
                # XAMPP Windows
                'C:\\xampp\\apache\\logs\\access.log',
                'C:\\xampp\\apache\\logs\\access_log',
                # WAMP Windows
                'C:\\wamp64\\logs\\access.log',
                'C:\\wamp\\logs\\access.log',
                # Generic Windows Apache
                'C:\\Apache24\\logs\\access.log',
                'C:\\Program Files\\Apache Software Foundation\\Apache2.4\\logs\\access.log',
            ],
            'nginx': [
                # Ubuntu/Debian/CentOS Nginx
                '/var/log/nginx/access.log',
                '/var/log/nginx/access_log',
                '/etc/nginx/logs/access.log',
                # Windows Nginx
                'C:\\nginx\\logs\\access.log',
                'C:\\nginx-1.20.1\\logs\\access.log',
                # XAMPP Nginx (if used)
                'C:\\xampp\\nginx\\logs\\access.log',
            ]
        }
        
        self.found_logs = []
    
    def find_log_files(self) -> List[Dict[str, str]]:
        """
        Find existing log files on the system
        Returns list of dicts with 'path' and 'type' keys
        """
        print("🔍 Searching for real Apache/Nginx log files...")
        found_files = []
        
        for server_type, paths in self.common_log_paths.items():
            for log_path in paths:
                if os.path.exists(log_path) and os.path.isfile(log_path):
                    # Check if file has recent content
                    try:
                        stat = os.stat(log_path)
                        size = stat.st_size
                        
                        if size > 0:
                            found_files.append({
                                'path': log_path,
                                'type': server_type,
                                'size_mb': round(size / 1024 / 1024, 2),
                                'modified': datetime.fromtimestamp(stat.st_mtime)
                            })
                            print(f"✅ Found {server_type} log: {log_path} ({round(size/1024/1024, 2)} MB)")
                        
                    except Exception as e:
                        print(f"⚠️ Cannot read {log_path}: {e}")
        
        # Also search for additional log files in common directories
        additional_logs = self._search_directories()
        found_files.extend(additional_logs)
        
        if not found_files:
            print("❌ No existing log files found!")
            print("💡 Suggestions:")
            print("   1. Start Apache/Nginx and generate some web traffic")
            print("   2. Check if logs are in a custom location")
            print("   3. Ensure you have read permissions to log directories")
        
        self.found_logs = found_files
        return found_files
    
    def _search_directories(self) -> List[Dict[str, str]]:
        """Search common directories for log files"""
        search_dirs = [
            '/var/log',
            '/opt/lampp/logs',  # XAMPP Linux
            'C:\\xampp\\apache\\logs',
            'C:\\wamp64\\logs',
            'C:\\nginx\\logs'
        ]
        
        additional_files = []
        
        for directory in search_dirs:
            if os.path.exists(directory):
                try:
                    for file in os.listdir(directory):
                        if 'access' in file.lower() and ('log' in file.lower() or file.endswith('.log')):
                            full_path = os.path.join(directory, file)
                            if os.path.isfile(full_path):
                                stat = os.stat(full_path)
                                if stat.st_size > 100:  # Only files with some content
                                    additional_files.append({
                                        'path': full_path,
                                        'type': 'unknown',
                                        'size_mb': round(stat.st_size / 1024 / 1024, 2),
                                        'modified': datetime.fromtimestamp(stat.st_mtime)
                                    })
                except (PermissionError, OSError):
                    continue
        
        return additional_files


class RealLogProcessor:
    """
    Process real Apache/Nginx log files with transformer analysis
    """
    
    def __init__(self):
        """Initialize real log processor"""
        self.log_finder = RealLogFinder()
        
        # Apache/Nginx log format patterns
        self.log_patterns = {
            'combined': re.compile(
                r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+) (?P<path>\S+) (?P<version>[^"]+)" '
                r'(?P<status>\d+) (?P<size>\S+) '
                r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
            ),
            'common': re.compile(
                r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+) (?P<path>\S+) (?P<version>[^"]+)" '
                r'(?P<status>\d+) (?P<size>\S+)'
            ),
            'nginx_default': re.compile(
                r'(?P<ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+) (?P<path>\S+) (?P<version>[^"]+)" '
                r'(?P<status>\d+) (?P<size>\S+) '
                r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
            )
        }
        
        # Load transformer
        if TRANSFORMER_AVAILABLE:
            try:
                print("🤖 Loading transformer for real log analysis...")
                self.transformer = WebAttackTransformer()
                print("✅ Transformer ready for real log analysis")
            except Exception as e:
                print(f"❌ Transformer loading failed: {e}")
                self.transformer = None
        else:
            self.transformer = None
        
        # Statistics
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'malicious_requests': 0,
            'benign_requests': 0,
            'errors': 0,
            'start_time': datetime.now()
        }
    
    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single log line from real Apache/Nginx logs"""
        self.stats['total_lines'] += 1
        line = line.strip()
        
        if not line or line.startswith('#'):
            return None
        
        # Try each log format pattern
        for format_name, pattern in self.log_patterns.items():
            match = pattern.match(line)
            if match:
                data = match.groupdict()
                
                # Extract request components
                method = data.get('method', 'GET')
                path = data.get('path', '/')
                
                parsed = {
                    'timestamp': data.get('timestamp', ''),
                    'ip': data.get('ip', ''),
                    'method': method,
                    'path': path,
                    'status': int(data.get('status', 0)),
                    'size': data.get('size', '0'),
                    'referer': data.get('referer', ''),
                    'user_agent': data.get('user_agent', ''),
                    'version': data.get('version', 'HTTP/1.1'),
                    'request_string': f"{method} {path}",  # This goes to transformer
                    'log_format': format_name,
                    'raw_line': line
                }
                
                self.stats['parsed_lines'] += 1
                return parsed
        
        # If no pattern matched, log it for debugging
        if len(line) > 20:  # Only log substantial lines
            logger.debug(f"Failed to parse: {line[:100]}...")
        
        return None
    
    def process_log_file(self, log_file_path: str, max_lines: int = None):
        """Process a single log file"""
        print(f"📄 Processing real log file: {log_file_path}")
        
        if not os.path.exists(log_file_path):
            print(f"❌ Log file not found: {log_file_path}")
            return
        
        try:
            processed_count = 0
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if max_lines and processed_count >= max_lines:
                        print(f"⚠️ Stopping at {max_lines} lines limit")
                        break
                    
                    parsed = self.parse_log_line(line)
                    
                    if parsed:
                        # Analyze with transformer
                        if self.transformer:
                            analysis = self._analyze_with_transformer(parsed)
                            parsed.update(analysis)
                            
                            # Display results
                            self._display_analysis(parsed)
                            
                            # Update stats
                            if analysis.get('is_malicious', False):
                                self.stats['malicious_requests'] += 1
                            else:
                                self.stats['benign_requests'] += 1
                        
                        processed_count += 1
                    
                    # Progress indicator for large files
                    if line_num % 1000 == 0:
                        print(f"   Processed {line_num:,} lines, found {processed_count} valid requests")
            
            print(f"✅ Completed processing {log_file_path}")
            print(f"   Total lines: {self.stats['total_lines']:,}")
            print(f"   Parsed requests: {self.stats['parsed_lines']:,}")
            print(f"   Success rate: {(self.stats['parsed_lines']/max(self.stats['total_lines'], 1)*100):.1f}%")
            
        except Exception as e:
            print(f"❌ Error processing {log_file_path}: {e}")
            self.stats['errors'] += 1
    
    def _analyze_with_transformer(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze parsed request with transformer"""
        try:
            request_string = parsed_request['request_string']
            result = self.transformer.predict_attack(request_string, use_transformer=True)
            
            return {
                'is_malicious': result['is_malicious'],
                'confidence': result['confidence'],
                'attack_type': result.get('attack_type', 'none'),
                'processing_time': result.get('processing_time_ms', 0),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return {
                'is_malicious': False,
                'confidence': 0.0,
                'attack_type': 'error',
                'error': str(e)
            }
    
    def _display_analysis(self, parsed_request: Dict[str, Any]):
        """Display analysis results"""
        timestamp = parsed_request.get('timestamp', 'unknown')
        ip = parsed_request.get('ip', 'unknown')
        request = parsed_request.get('request_string', 'unknown')
        status = parsed_request.get('status', 0)
        
        if parsed_request.get('is_malicious', False):
            attack_type = parsed_request.get('attack_type', 'unknown')
            confidence = parsed_request.get('confidence', 0)
            
            print(f"🚫 ATTACK DETECTED:")
            print(f"   Time: {timestamp}")
            print(f"   IP: {ip}")
            print(f"   Request: {request}")
            print(f"   Attack Type: {attack_type}")
            print(f"   Confidence: {confidence:.2f}")
            print(f"   Status: {status}")
            print()
        else:
            # Only show benign requests occasionally to avoid spam
            if self.stats['benign_requests'] % 20 == 0 or self.stats['benign_requests'] < 5:
                print(f"✅ BENIGN: {request} from {ip} (status: {status})")
    
    def print_final_stats(self):
        """Print final processing statistics"""
        runtime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        print("\n" + "="*60)
        print("📊 FINAL ANALYSIS STATISTICS")
        print("="*60)
        print(f"Processing Time: {runtime:.1f} seconds")
        print(f"Total Log Lines: {self.stats['total_lines']:,}")
        print(f"Parsed Requests: {self.stats['parsed_lines']:,}")
        print(f"Malicious Requests: {self.stats['malicious_requests']:,}")
        print(f"Benign Requests: {self.stats['benign_requests']:,}")
        print(f"Processing Errors: {self.stats['errors']:,}")
        
        if self.stats['parsed_lines'] > 0:
            threat_rate = (self.stats['malicious_requests'] / self.stats['parsed_lines']) * 100
            print(f"Threat Rate: {threat_rate:.2f}%")
        
        if runtime > 0:
            print(f"Processing Speed: {self.stats['parsed_lines']/runtime:.1f} requests/second")


def main():
    """Main function to run real log ingestion"""
    print("🔥 REAL APACHE/NGINX LOG INGESTION")
    print("="*60)
    print("Reading from actual web server log files")
    print("="*60)
    
    # Find real log files
    processor = RealLogProcessor()
    found_logs = processor.log_finder.find_log_files()
    
    if not found_logs:
        print("\n💡 How to generate real logs:")
        print("1. Install Apache/Nginx:")
        print("   - Ubuntu: sudo apt install apache2 nginx")
        print("   - Windows: Download XAMPP from https://www.apachefriends.org/")
        print("2. Start the web server")
        print("3. Browse to http://localhost to generate traffic")
        print("4. Try these test URLs:")
        print("   - http://localhost/")
        print("   - http://localhost/admin")  
        print("   - http://localhost/search?q=test")
        print("5. Run this script again")
        return
    
    print(f"\n📋 Found {len(found_logs)} log files:")
    for i, log_info in enumerate(found_logs):
        print(f"  {i+1}. {log_info['path']} ({log_info['type']}, {log_info['size_mb']} MB)")
    
    # Process each log file
    print(f"\n🔄 Starting analysis of real log files...")
    
    for log_info in found_logs:
        print(f"\n{'='*60}")
        print(f"Processing: {log_info['path']}")
        print(f"Type: {log_info['type']} | Size: {log_info['size_mb']} MB")
        print('='*60)
        
        # Process the log file (limit to 1000 lines for demo)
        processor.process_log_file(log_info['path'], max_lines=1000)
        
        # Small delay between files
        time.sleep(1)
    
    # Show final statistics
    processor.print_final_stats()
    
    print(f"\n🎉 Real log analysis completed!")
    print("Your transformer analyzed actual web server logs! 🛡️")


if __name__ == "__main__":
    main()