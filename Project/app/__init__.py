import os
from flask import Flask
from .extensions import db, migrate

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    
    db_path = os.path.join(app.instance_path, 'local.db')
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-key'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,

        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', f'sqlite:///{db_path}'),
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)
    migrate.init_app(app, db)
    from . import models 
    from .extensions import login_manager
    login_manager.init_app(app)

   
    # Register blueprints
    from .routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app