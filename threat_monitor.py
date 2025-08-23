import psutil
import time
import logging
import threading
from datetime import datetime, timedelta
from app import db
from models import SystemMetrics, ThreatAlert

class ThreatMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.alert_thresholds = {
            'cpu_usage': 90.0,
            'memory_usage': 85.0,
            'disk_usage': 95.0,
            'suspicious_processes': 10,
            'network_activity': 100.0  # MB/s
        }
        
        # Known suspicious process patterns
        self.suspicious_process_patterns = [
            'cryptolocker', 'wannacry', 'petya', 'ransomware',
            'encrypt', 'crypt', 'locked', 'ransom'
        ]
    
    def start_monitoring(self):
        """Start system monitoring in background thread"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            logging.info("Threat monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logging.info("Threat monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                metrics = self.collect_system_metrics()
                self.analyze_metrics(metrics)
                self.store_metrics(metrics)
                time.sleep(60)  # Check every minute
            except Exception as e:
                logging.error(f"Monitoring loop error: {e}")
                time.sleep(10)
    
    def collect_system_metrics(self):
        """Collect current system metrics"""
        try:
            # CPU usage
            cpu_usage = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_usage = (disk.used / disk.total) * 100
            
            # Network activity
            network_io = psutil.net_io_counters()
            network_activity = (network_io.bytes_sent + network_io.bytes_recv) / (1024 * 1024)  # MB
            
            # Process information
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
            active_processes = len(processes)
            
            # Check for suspicious processes
            suspicious_processes = self.detect_suspicious_processes(processes)
            
            return {
                'timestamp': datetime.utcnow(),
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage,
                'disk_usage': disk_usage,
                'network_activity': network_activity,
                'active_processes': active_processes,
                'suspicious_processes': suspicious_processes,
                'threat_level': self.calculate_threat_level({
                    'cpu_usage': cpu_usage,
                    'memory_usage': memory_usage,
                    'disk_usage': disk_usage,
                    'suspicious_processes': len(suspicious_processes)
                })
            }
            
        except Exception as e:
            logging.error(f"Metrics collection error: {e}")
            return None
    
    def detect_suspicious_processes(self, processes):
        """Detect potentially suspicious processes"""
        suspicious = []
        
        for proc in processes:
            try:
                process_name = proc.info['name'].lower()
                
                # Check against known patterns
                for pattern in self.suspicious_process_patterns:
                    if pattern in process_name:
                        suspicious.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cpu_percent': proc.info['cpu_percent'],
                            'memory_percent': proc.info['memory_percent'],
                            'reason': f'Matches suspicious pattern: {pattern}'
                        })
                        break
                
                # Check for high resource usage
                if (proc.info['cpu_percent'] > 50 and 
                    proc.info['memory_percent'] > 20):
                    suspicious.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_percent': proc.info['memory_percent'],
                        'reason': 'High resource usage'
                    })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return suspicious
    
    def calculate_threat_level(self, metrics):
        """Calculate overall system threat level"""
        threat_score = 0
        
        # CPU usage factor
        if metrics['cpu_usage'] > 80:
            threat_score += 2
        elif metrics['cpu_usage'] > 60:
            threat_score += 1
        
        # Memory usage factor
        if metrics['memory_usage'] > 80:
            threat_score += 2
        elif metrics['memory_usage'] > 60:
            threat_score += 1
        
        # Disk usage factor
        if metrics['disk_usage'] > 90:
            threat_score += 3
        elif metrics['disk_usage'] > 75:
            threat_score += 1
        
        # Suspicious processes factor
        if metrics['suspicious_processes'] > 0:
            threat_score += metrics['suspicious_processes'] * 2
        
        # Determine threat level
        if threat_score >= 6:
            return 'critical'
        elif threat_score >= 4:
            return 'high'
        elif threat_score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def analyze_metrics(self, metrics):
        """Analyze metrics and generate alerts if necessary"""
        if not metrics:
            return
        
        alerts = []
        
        # Check CPU usage
        if metrics['cpu_usage'] > self.alert_thresholds['cpu_usage']:
            alerts.append({
                'type': 'cpu_high',
                'message': f"High CPU usage detected: {metrics['cpu_usage']:.1f}%",
                'severity': 'warning'
            })
        
        # Check memory usage
        if metrics['memory_usage'] > self.alert_thresholds['memory_usage']:
            alerts.append({
                'type': 'memory_high',
                'message': f"High memory usage detected: {metrics['memory_usage']:.1f}%",
                'severity': 'warning'
            })
        
        # Check disk usage
        if metrics['disk_usage'] > self.alert_thresholds['disk_usage']:
            alerts.append({
                'type': 'disk_high',
                'message': f"High disk usage detected: {metrics['disk_usage']:.1f}%",
                'severity': 'critical'
            })
        
        # Check suspicious processes
        if metrics['suspicious_processes']:
            for proc in metrics['suspicious_processes']:
                alerts.append({
                    'type': 'suspicious_process',
                    'message': f"Suspicious process detected: {proc['name']} (PID: {proc['pid']}) - {proc['reason']}",
                    'severity': 'high'
                })
        
        # Create alert records
        for alert in alerts:
            self.create_alert(alert)
    
    def create_alert(self, alert_data):
        """Create an alert record in the database"""
        try:
            alert = ThreatAlert(
                user_id=1,  # System alerts for all users
                alert_type=alert_data['type'],
                message=alert_data['message'],
                severity=alert_data['severity']
            )
            
            db.session.add(alert)
            db.session.commit()
            
            logging.warning(f"Alert created: {alert_data['message']}")
            
        except Exception as e:
            logging.error(f"Alert creation error: {e}")
            db.session.rollback()
    
    def store_metrics(self, metrics):
        """Store system metrics in database"""
        if not metrics:
            return
        
        try:
            system_metrics = SystemMetrics(
                timestamp=metrics['timestamp'],
                cpu_usage=metrics['cpu_usage'],
                memory_usage=metrics['memory_usage'],
                disk_usage=metrics['disk_usage'],
                network_activity=metrics['network_activity'],
                active_processes=metrics['active_processes'],
                threat_level=metrics['threat_level']
            )
            
            db.session.add(system_metrics)
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Metrics storage error: {e}")
            db.session.rollback()
    
    def get_current_metrics(self):
        """Get current system metrics for API"""
        try:
            metrics = self.collect_system_metrics()
            if metrics:
                return {
                    'cpu_usage': metrics['cpu_usage'],
                    'memory_usage': metrics['memory_usage'],
                    'disk_usage': metrics['disk_usage'],
                    'network_activity': metrics['network_activity'],
                    'active_processes': metrics['active_processes'],
                    'threat_level': metrics['threat_level'],
                    'suspicious_processes': len(metrics['suspicious_processes']),
                    'timestamp': metrics['timestamp'].isoformat()
                }
            else:
                return {'error': 'Unable to collect metrics'}
        except Exception as e:
            logging.error(f"Current metrics error: {e}")
            return {'error': str(e)}
    
    def get_historical_metrics(self, hours=24):
        """Get historical metrics for charting"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            metrics = SystemMetrics.query.filter(
                SystemMetrics.timestamp >= cutoff_time
            ).order_by(SystemMetrics.timestamp).all()
            
            return [{
                'timestamp': m.timestamp.isoformat(),
                'cpu_usage': m.cpu_usage,
                'memory_usage': m.memory_usage,
                'disk_usage': m.disk_usage,
                'threat_level': m.threat_level
            } for m in metrics]
            
        except Exception as e:
            logging.error(f"Historical metrics error: {e}")
            return []
    
    def cleanup_old_metrics(self, days=30):
        """Clean up old metrics data"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=days)
            
            old_metrics = SystemMetrics.query.filter(
                SystemMetrics.timestamp < cutoff_time
            ).delete()
            
            db.session.commit()
            logging.info(f"Cleaned up {old_metrics} old metric records")
            
        except Exception as e:
            logging.error(f"Metrics cleanup error: {e}")
            db.session.rollback()
