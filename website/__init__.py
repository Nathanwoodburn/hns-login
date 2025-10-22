import os
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.from_object(os.environ['APP_SETTINGS'])

    # Import models after app creation but before init_db
    from .models import db, User
    db.init_app(app)
    
    # Run migrations to fix schema issues
    from .migrations import add_missing_columns_to_oauth2_code
    add_missing_columns_to_oauth2_code(app)
    
    return app