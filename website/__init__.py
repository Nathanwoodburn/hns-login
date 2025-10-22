import os
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.from_object(os.environ['APP_SETTINGS'])

    with app.app_context():
        # Run migrations first, before any database operations
        from .migrations import add_missing_columns_to_oauth2_code
        add_missing_columns_to_oauth2_code(app)
        
        # Import models after migration but before init_db
        from .models import db
        db.create_all()
    
    return app