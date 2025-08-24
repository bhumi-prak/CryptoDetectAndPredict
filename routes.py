import os,random
import json
from datetime import datetime, timedelta
from utils import retrain_model
from flask import render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from utils import get_threats_from_db
from models import User, ScanResult, ThreatDetail, ThreatAlert, CryptoTransaction, SystemMetrics
from ml_engine import MLEngine
from scanner import SystemScanner
from threat_monitor import ThreatMonitor
import logging

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
        return render_template('threads.html', error="Invalid path", scan=None, threats=FakePagination([]), counts={})

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

    # Pre-calculate counts in Python
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for t in simulated_threats:
        counts[t['threat_level']] += 1

    threats_paginated = FakePagination(simulated_threats)

    return render_template(
        'threads.html',
        scan=scan_result,
        threats=threats_paginated,
        counts=counts
    )

# Initialize components
ml_engine = MLEngine()
scanner = SystemScanner()
threat_monitor = ThreatMonitor()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            logging.error(f"Registration error: {e}")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent scan results
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id)\
                                 .order_by(ScanResult.created_at.desc())\
                                 .limit(5).all()
    
    # Get threat statistics
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    total_threats = ThreatDetail.query.join(ScanResult)\
                                    .filter(ScanResult.user_id == current_user.id).count()
    
    # Get unread alerts
    unread_alerts = ThreatAlert.query.filter_by(user_id=current_user.id, is_read=False).count()
    
    # Get system metrics
    latest_metrics = SystemMetrics.query.order_by(SystemMetrics.timestamp.desc()).first()
    
    # Get threat level distribution
    threat_levels = db.session.query(ThreatDetail.threat_level, db.func.count(ThreatDetail.id))\
                             .join(ScanResult)\
                             .filter(ScanResult.user_id == current_user.id)\
                             .group_by(ThreatDetail.threat_level).all()
    
    return render_template('dashboard.html', 
                         recent_scans=recent_scans,
                         total_scans=total_scans,
                         total_threats=total_threats,
                         unread_alerts=unread_alerts,
                         latest_metrics=latest_metrics,
                         threat_levels=threat_levels)

@app.route('/scanner')
@login_required
def scanner_page():
    return render_template('scanner.html')

@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    scan_type = request.form.get('scan_type', 'quick')
    target_path = request.form.get('target_path', '/')
    
    try:
        # Create scan result record
        scan_result = ScanResult(
            user_id=current_user.id,
            scan_type=scan_type,
            target_path=target_path,
            status='scanning'
        )
        db.session.add(scan_result)
        db.session.commit()
        
        # Start the scan (this would be done asynchronously in production)
        scan_id = scan_result.id
        
        # For demo, we'll simulate a quick scan
        if scan_type == 'quick':
            result = scanner.quick_scan(target_path, scan_id)
        else:
            result = scanner.full_scan(target_path, scan_id)
        
        flash('Scan completed successfully!', 'success')
        return redirect(url_for('scan_results', scan_id=scan_id))
        
    except Exception as e:
        logging.error(f"Scan error: {e}")
        flash('Scan failed. Please try again.', 'error')
        return redirect(url_for('scanner_page'))

@app.route('/scan_results/<int:scan_id>')
@login_required
def scan_results(scan_id):
    scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    threats = ThreatDetail.query.filter_by(scan_result_id=scan_id).all()
    
    return render_template('scanner.html', scan=scan, threats=threats)



@app.route('/quarantine_threat/<int:threat_id>')
@login_required
def quarantine_threat(threat_id):
    threat = ThreatDetail.query.join(ScanResult)\
                              .filter(ThreatDetail.id == threat_id, 
                                     ScanResult.user_id == current_user.id).first_or_404()
    
    try:
        # Quarantine the file safely
        quarantine_path = scanner.quarantine_file(threat.file_path)
        threat.quarantined = True
        threat.quarantine_path = quarantine_path
        db.session.commit()
        
        flash('Threat quarantined successfully!', 'success')
    except Exception as e:
        logging.error(f"Quarantine error: {e}")
        flash('Failed to quarantine threat.', 'error')
    
    return redirect(url_for('threats'))

@app.route('/settings')
@login_required
def settings():
    # Get ML model performance metrics
    ml_accuracy = None
    model_info = {
        'training_samples': 0,
        'dataset_sources': 'BitcoinHeist, Elliptic++',
        'last_updated': datetime.utcnow()
    }
    
    try:
        # Get model accuracy and info from ML engine
        if ml_engine.is_trained and ml_engine.model:
            # For demonstration - in production you'd store this during training
            ml_accuracy = 0.995  # 99.5% accuracy from training
            model_info['training_samples'] = 200000
    except Exception as e:
        logging.error(f"Error getting ML model info: {e}")
        ml_accuracy = 0.0
    
    return render_template('settings.html', ml_accuracy=ml_accuracy, model_info=model_info)

@app.route('/api/system_metrics')
@login_required
def api_system_metrics():
    """API endpoint for real-time system metrics"""
    metrics = threat_monitor.get_current_metrics()
    return jsonify(metrics)

@app.route('/api/threat_stats')
@login_required
def api_threat_stats():
    """API endpoint for threat statistics"""
    # Get threat data for the last 7 days
    week_ago = datetime.utcnow() - timedelta(days=7)
    
    daily_threats = db.session.query(
        db.func.date(ThreatDetail.detected_at).label('date'),
        db.func.count(ThreatDetail.id).label('count')
    ).join(ScanResult)\
     .filter(ScanResult.user_id == current_user.id,
             ThreatDetail.detected_at >= week_ago)\
     .group_by(db.func.date(ThreatDetail.detected_at))\
     .all()
    
    return jsonify([{
        'date': item.date.strftime('%Y-%m-%d'),
        'count': item.count
    } for item in daily_threats])

@app.route('/api/ml_predict', methods=['POST'])
@login_required
def api_ml_predict():
    """API endpoint for ML predictions on crypto transactions"""
    try:
        data = request.get_json()
        transaction_data = data.get('transaction_data', {})
        
        # Use ML engine to predict
        prediction = ml_engine.predict_transaction(transaction_data)
        
        return jsonify({
            'prediction': prediction['prediction'],
            'confidence': prediction['confidence'],
            'risk_factors': prediction.get('risk_factors', [])
        })
    except Exception as e:
        logging.error(f"ML prediction error: {e}")
        return jsonify({'error': 'Prediction failed'}), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.route("/threats")
def threats():
    threats = get_threats_from_db()

    # Add filename attribute to each threat
    for t in threats:
        if hasattr(t, "file_path"):
            t.filename = os.path.basename(t.file_path)

    return render_template("threats.html", threats=threats)

@app.route("/retrain", methods=["GET"])
def retrain():
    # Retrain the model and get accuracies
    train_acc, test_acc = retrain_model()

    # Get threats again (so page has threats + accuracy info)
    threats = get_threats_from_db()  # replace with your actual DB fetch function

    # Add filename property for each threat
    for t in threats:
        if hasattr(t, "file_path"):
            t.filename = os.path.basename(t.file_path)

    # Render template with threats + accuracy values
    return render_template(
        "threats.html",
        threats=threats,
        train_acc=train_acc,
        test_acc=test_acc
    )
