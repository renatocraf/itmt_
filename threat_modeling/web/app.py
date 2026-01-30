"""Flask application factory - Creates app with session, config, and main blueprint."""
from flask import Flask
from flask_session import Session
import os
from threat_modeling.config.settings import DATA_DIR


def create_app(config_name='development'):
    """
    Create and configure the Flask application (secret, upload limit, session, blueprint).

    Args:
        config_name: Unused; kept for compatibility (default 'development').

    Returns:
        Configured Flask app instance with main_bp registered.
    """
    app = Flask(
        __name__,
        template_folder='templates',
        static_folder='../static'
    )
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    app.config['UPLOAD_FOLDER'] = DATA_DIR
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_TIME_LIMIT'] = None  # Disable CSRF timeout for file uploads
    
    # Flask-Session configuration
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = os.path.join(DATA_DIR, 'flask_session')
    app.config['SESSION_FILE_THRESHOLD'] = 100
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_KEY_PREFIX'] = 'threat_modeling:'
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Ensure directories exist
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    
    # Initialize Flask-Session
    Session(app)
    
    # Register blueprints
    from threat_modeling.web.routes import main_bp
    app.register_blueprint(main_bp)
    
    return app

