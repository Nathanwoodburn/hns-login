import os
import sqlite3
from sqlalchemy import inspect
from flask import current_app
import logging

def add_missing_columns_to_oauth2_code(app):
    """
    Check and add missing columns to oauth2_code table
    """
    print("Starting database migration check...")
    with app.app_context():
        from website.models import db
        
        # Get the engine and inspector
        engine = db.engine
        inspector = inspect(engine)
        
        # Check if oauth2_code table exists
        if 'oauth2_code' not in inspector.get_table_names():
            print("oauth2_code table doesn't exist yet, skipping migration")
            return  # Table doesn't exist yet
            
        # Get existing columns
        columns = [column['name'] for column in inspector.get_columns('oauth2_code')]
        print(f"Existing columns in oauth2_code: {columns}")
        
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
            print("No columns need to be added, schema is up to date")
            return  # No columns need to be added
        
        print(f"Columns to add: {columns_to_add}")
        
        # Connect directly to SQLite to add columns
        try:
            # Get database URI from app config
            db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI')
            print(f"Database URI: {db_uri}")
            
            # Handle both relative and absolute paths
            if db_uri.startswith('sqlite:///'):
                # Relative path
                if db_uri.startswith('sqlite:////'):
                    # Absolute path
                    db_path = db_uri.replace('sqlite:////', '/')
                else:
                    # Relative path - may need to be adjusted for Docker
                    db_path = os.path.join(app.root_path, '..', db_uri.replace('sqlite:///', ''))
            else:
                # Memory or other type of database
                print(f"Unsupported database type: {db_uri}")
                return
                
            print(f"Attempting to connect to database at: {db_path}")
            
            # Ensure directory exists
            db_dir = os.path.dirname(db_path)
            if not os.path.exists(db_dir):
                print(f"Database directory doesn't exist: {db_dir}")
            
            # Connect to database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            for column, dtype in columns_to_add.items():
                try:
                    sql = f'ALTER TABLE oauth2_code ADD COLUMN {column} {dtype};'
                    print(f"Executing SQL: {sql}")
                    cursor.execute(sql)
                    print(f"Successfully added column '{column}' to oauth2_code table")
                except sqlite3.OperationalError as e:
                    print(f"Error adding column '{column}': {str(e)}")
            
            conn.commit()
            conn.close()
            print("Migration completed successfully")
        except Exception as e:
            print(f"Error during migration: {str(e)}")
            import traceback
            traceback.print_exc()
