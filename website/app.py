import os
from flask import Flask
from .models import db
from .oauth2 import config_oauth
from .routes import bp
from datetime import timedelta
import dotenv

dotenv.load_dotenv()

def create_app(config=None):
    app = Flask(__name__)

    # load default configuration
    app.config.from_object('website.settings')

    # load environment configuration
    if 'WEBSITE_CONF' in os.environ:
        app.config.from_envvar('WEBSITE_CONF')

    # Set the secret key to a key from the ENV
    app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24).hex())

    # Set the session to be permanent
    app.config["SESSION_PERMANENT"] = True

    # Set it to 6 months
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=180)

    # load app specified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)
    setup_app(app)
    return app


def setup_app(app: Flask):

    db.init_app(app)
    # Create tables if they do not exist already
    with app.app_context():
        db.create_all()
    config_oauth(app)
    app.register_blueprint(bp, url_prefix='')