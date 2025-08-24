from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship to scan results
    scan_results = db.relationship('ScanResult', backref='user', lazy=True)
    threat_alerts = db.relationship('ThreatAlert', backref='user', lazy=True)

    @property
    def threat_details(self):
        details = []
        for scan in self.scan_results:
            details.extend(scan.threats)
        return details

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # 'full_system', 'directory', 'file'
    target_path = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'scanning', 'completed', 'failed'
    threats_found = db.Column(db.Integer, default=0)
    files_scanned = db.Column(db.Integer, default=0)
    scan_duration = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # Relationship to threat details
    threats = db.relationship('ThreatDetail', backref='scan_result', lazy=True)

class ThreatDetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    threat_type = db.Column(db.String(100), nullable=False)
    threat_level = db.Column(db.String(20), nullable=False)  # 'low', 'medium', 'high', 'critical'
    confidence_score = db.Column(db.Float, nullable=False)
    file_hash = db.Column(db.String(64))
    file_size = db.Column(db.Integer)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    quarantined = db.Column(db.Boolean, default=False)
    quarantine_path = db.Column(db.String(500))

class ThreatAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CryptoTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_hash = db.Column(db.String(64), unique=True, nullable=False)
    address = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    prediction = db.Column(db.String(20))  # 'legitimate', 'suspicious', 'ransomware'
    confidence = db.Column(db.Float)
    features = db.Column(db.JSON)  # Store extracted features as JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SystemMetrics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    disk_usage = db.Column(db.Float)
    network_activity = db.Column(db.Float)
    active_processes = db.Column(db.Integer)
    threat_level = db.Column(db.String(20), default='low')

import sqlite3

def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        threat_level TEXT NOT NULL,
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()


