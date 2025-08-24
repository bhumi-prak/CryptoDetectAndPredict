import os
import logging
from datetime import datetime
import random
from flask import render_template, request
from flask_login import login_required, current_user
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager, current_user, login_required
from dotenv import load_dotenv

# ---------------- Environment ----------------
load_dotenv()
logging.basicConfig(level=logging.DEBUG)

# ---------------- Flask App Setup ----------------
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or os.urandom(24)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///ransomware_detector.db"
)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_recycle": 300, "pool_pre_ping": True}

db.init_app(app)

# ---------------- Flask-Login ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

with app.app_context():
    import models
    db.create_all()
    logging.info("Database tables created")

# ---------------- Jinja2 Filters ----------------
@app.template_filter('basename')
def basename_filter(path):
    return os.path.basename(path)

@app.template_filter('dirname')
def dirname_filter(path):
    return os.path.dirname(path)

class FakePagination:
    """Simulate a paginated object for template compatibility."""
    def __init__(self, items):
        self.items = items
        self.total = len(items)
        self.page = 1
        self.pages = 1
        self.has_prev = False
        self.has_next = False

    def iter_pages(self):
        return [1]

@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan_route():
    target_path = request.form.get('target_path')
    scan_type = request.form.get('scan_type', 'quick')

    if not target_path or not os.path.exists(target_path):
        return render_template('threads.html', error="Invalid path", scan=None, threats=FakePagination([]))

    # --- Simulate threats ---
    simulated_threats = []
    for i in range(5):
        simulated_threats.append({
            'id': i+1,
            'file_path': f"/simulated/path/fake_threat_{i}.exe",
            'threat_level': random.choice(['low','medium','high','critical']),
            'confidence_score': round(random.uniform(0.7, 0.99), 2),
            'detected_at': datetime.utcnow(),
            'quarantined': False,
            'file_size': random.randint(50_000, 5_000_000),
            'file_hash': f"{random.getrandbits(128):032x}",
            'threat_type': 'Ransomware Indicator'
        })

    scan_result = {
        'files_scanned': 1000,
        'threats_found': len(simulated_threats),
        'threat_details': simulated_threats,
        'scan_duration': 12.5,
        'status': 'completed'
    }

    threats_paginated = FakePagination(simulated_threats)

    return render_template(
        'threads.html',
        scan=scan_result,
        threats=threats_paginated
    )
# ---------------- Placeholder File Analyzer ----------------
class ScanResult:
    def __init__(self, file_path, is_threat=False, entropy=None):
        self.file_path = file_path
        self.is_threat = is_threat
        self.entropy = entropy

def analyze_file(filepath):
    """Simple placeholder for file analysis"""
    is_threat = filepath.endswith(".exe")
    entropy = 7.2 if is_threat else 3.0
    return ScanResult(filepath, is_threat=is_threat, entropy=entropy)

# ---------------- Safe Scanner ----------------
def start_scan(target_path, scan_type='quick'):
    files_scanned = 0
    threats_found = []

    for root, dirs, files in os.walk(target_path):
        if 'node_modules' in dirs:
            dirs.remove('node_modules')

        for file in files:
            if file.endswith(('.js', '.map', '.json')):
                continue

            filepath = os.path.join(root, file)
            files_scanned += 1

            try:
                result = analyze_file(filepath)
                # Handle potential float.bit_length issues
                try:
                    if hasattr(result, 'entropy'):
                        result.entropy.bit_length()
                except AttributeError:
                    pass

                if getattr(result, 'is_threat', False):
                    threats_found.append(result)

            except Exception as e:
                logging.warning(f"Skipping {filepath}: {e}")
                continue

    return {
        'files_scanned': files_scanned,
        'threats_found': len(threats_found),
        'threat_details': threats_found,
        'status': 'completed'
    }

# ---------------- Flask Routes ----------------
@app.route("/scanner")
@login_required
def scanner():
    # Ensure user attributes exist
    if not hasattr(current_user, 'scan_results') or current_user.scan_results is None:
        current_user.scan_results = []

    if not hasattr(current_user, 'threat_alerts') or current_user.threat_alerts is None:
        current_user.threat_alerts = []

    last_scan = current_user.scan_results[-1] if current_user.scan_results else None
    detected_threats = getattr(last_scan, 'threat_details', []) if last_scan else []

    return render_template(
        "scanner.html",
        scan=last_scan,
        threats=detected_threats
    )

@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan_route():
    target_path = request.form.get('target_path')
    scan_type = request.form.get('scan_type', 'quick')

    # If path is invalid, return empty scan
    if not target_path or not os.path.exists(target_path):
        return render_template('scanner.html', error="Invalid path", scan=None, threats=[])

    # --- Simulate threats ---
    simulated_threats = []
    for i in range(5):  # simulate 5 threats
        simulated_threats.append({
            'id': i+1,
            'file_path': f"/simulated/path/fake_threat_{i}.exe",
            'threat_level': random.choice(['low','medium','high','critical']),
            'confidence_score': round(random.uniform(0.7, 0.99), 2),
            'detected_at': datetime.utcnow(),
            'quarantined': False,
            'file_size': random.randint(50_000, 5_000_000),  # bytes
            'file_hash': f"{random.getrandbits(128):032x}",
            'threat_type': 'Ransomware Indicator'
        })

    scan_result = {
        'files_scanned': 1000,
        'threats_found': len(simulated_threats),
        'threat_details': simulated_threats,
        'scan_duration': 12.5,
        'status': 'completed'
    }
    # Do not append dicts to SQLAlchemy; just keep in memory for template
    # Optionally, store serialized results in DB if desired

    return render_template(
        'scanner.html',
        scan=scan_result,
        threats=scan_result['threat_details']
    )

# ---------------- Import additional routes ----------------
import routes
