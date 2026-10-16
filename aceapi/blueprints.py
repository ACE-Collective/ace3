from flask import Blueprint, Flask

hunt_bp = Blueprint('hunt', __name__, url_prefix='/hunt')

def register_blueprints(flask_app: Flask):
    import aceapi.hunt

    flask_app.register_blueprint(hunt_bp)
