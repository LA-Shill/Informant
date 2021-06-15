# !/usr/bin/env python
# Name:     __init__.py
# By:       LA-Shill
# Date:     01.08.2020
# Version   0.1
# -----------------------------------------------

# Import libraries
from flask import Flask
from flask_pymongo import PyMongo

# Set globally accessible libraries
mainDB = PyMongo()
vulDB = PyMongo()

def create_app():
    """Initialize core application."""
    app = Flask(__name__, instance_relative_config=False)
    #app.jinja_env.add_extension('jinja2.ext.loopcontrols')
    app.config.from_object('config.DevConfig') # config.DevConfig, config.ProdConfig, config.Config

    # Initialize databases
    mainDB.init_app(app, uri=app.config['CORE_MONGO_DB'])
    vulDB.init_app(app, uri=app.config['VUL_MONGO_DB'])
    
    # Everything in here is part of the 'visbile' app (register blueprints etc...)
    with app.app_context():
        # Include routes
        from .home import home
        # Register blueprints
        app.register_blueprint(home.home_bp)
        # Return app
        return app