import os
from flask import Flask
from . import models
def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-key-do-not-use-in-prod'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL'),
    )
    from .extensions import db
    db.init_app(app)
    
    from .extensions import db, migrate
    db.init_app(app)
    migrate.init_app(app, db)

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass


    
    return app