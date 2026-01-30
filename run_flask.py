"""Flask Application Entry Point"""
import os
from threat_modeling.web.app import create_app

app = create_app()

if __name__ == '__main__':
    # Get port from environment or default to 5000
    port = int(os.getenv('PORT', 5000))
    # Get host from environment or default to localhost
    host = os.getenv('HOST', '127.0.0.1')
    # Run in debug mode if FLASK_DEBUG is set
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(host=host, port=port, debug=debug)

