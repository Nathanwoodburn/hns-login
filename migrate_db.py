#!/usr/bin/env python3

from website import create_app
from website.migrations import add_missing_columns_to_oauth2_code

if __name__ == '__main__':
    app = create_app()
    print("Running database migration...")
    add_missing_columns_to_oauth2_code(app)
    print("Migration completed.")
