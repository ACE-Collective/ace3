from flask import Blueprint, Flask

analysis = Blueprint("analysis", __name__)
main = Blueprint('main', __name__)
events = Blueprint('events', __name__, url_prefix='/events')
auth = Blueprint('auth', __name__)
remediation = Blueprint('remediation', __name__)
file_collection = Blueprint('file_collection', __name__)

def register_blueprints(flask_app: Flask):
    import app.main
    import app.auth
    import app.analysis
    import app.events
    import app.remediation
    import app.file_collection

    flask_app.register_blueprint(main)
    flask_app.register_blueprint(auth)
    flask_app.register_blueprint(analysis)
    flask_app.register_blueprint(events)
    flask_app.register_blueprint(remediation)
    flask_app.register_blueprint(file_collection)