import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager
from dotenv import load_dotenv  # Added to load .env file

# ❌ REMOVE this line (it causes circular import)
# from app import app  

# Load environment variables from .env
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# ✅ Create the app here
app = Flask(__name__)

# Set secret key from environment or generate a secure fallback for development
app.secret_key = os.environ.get("SESSION_SECRET") or os.urandom(24)

# Apply ProxyFix middleware
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///ransomware_detector.db"
)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Initialize Flask-Login
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
    # Import models to ensure tables are created
    import models
    db.create_all()
    logging.info("Database tables created")


# ✅ Place your custom Jinja2 filter here
@app.template_filter('basename')
def basename_filter(path):
    return os.path.basename(path)


# Import routes *after* app is created (to avoid circular imports)
import routes

@app.template_filter('dirname')
def dirname_filter(path):
    return os.path.dirname(path)