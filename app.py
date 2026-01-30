"""Application entry point (alternative to run_flask.py). Exposes Flask app for 'flask run'."""
from threat_modeling.web.app import create_app

app = create_app()
