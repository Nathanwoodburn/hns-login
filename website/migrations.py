import sqlite3
from sqlalchemy import inspect
from flask import current_app

def add_missing_columns_to_oauth2_code(app):
    """
    Check and add missing columns to oauth2_code table
    """
    with app.app_context():
        from website.models import db
        
        # Get the engine and inspector
        engine = db.engine
        inspector = inspect(engine)
        
        # Check if oauth2_code table exists
        if 'oauth2_code' not in inspector.get_table_names():
            return  # Table doesn't exist yet
            
        # Get existing columns
        columns = [column['name'] for column in inspector.get_columns('oauth2_code')]
        
        # Define columns that should be added if missing
        missing_columns = {
            'acr': 'TEXT',
            'amr': 'TEXT',
            'code_challenge': 'TEXT',
            'code_challenge_method': 'TEXT'
        }
        
        # Check which columns need to be added
        columns_to_add = {col: dtype for col, dtype in missing_columns.items() if col not in columns}
        
        if not columns_to_add:
            return  # No columns need to be added
        
        # Connect directly to SQLite to add columns
        try:
            db_path = current_app.config.get('SQLALCHEMY_DATABASE_URI').replace('sqlite:///', '')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            for column, dtype in columns_to_add.items():
                try:
                    cursor.execute(f'ALTER TABLE oauth2_code ADD COLUMN {column} {dtype};')
                    print(f"Added missing column '{column}' to oauth2_code table")
                except sqlite3.OperationalError as e:
                    # Column might have been added in a concurrent process
                    print(f"Note: {str(e)}")
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error during migration: {str(e)}")
