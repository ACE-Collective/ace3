from flask import Blueprint, Flask

analysis = Blueprint("analysis", __name__)
main = Blueprint('main', __name__)
events = Blueprint('events', __name__, url_prefix='/events')
auth = Blueprint('auth', __name__)
admin = Blueprint('admin', __name__, url_prefix='/admin')
signatures = Blueprint('signatures', __name__, url_prefix='/signatures')
svs = Blueprint('svs', __name__, url_prefix='/svs')
feeds = Blueprint('feeds', __name__, url_prefix='/feeds')
help_pages = Blueprint('help', __name__, url_prefix='/help')
remediation = Blueprint('remediation', __name__)
file_collection = Blueprint('file_collection', __name__)

def register_blueprints(flask_app: Flask):
    import app.main
    import app.auth
    import app.admin
    import app.signatures
    import app.svs
    # imported here like the others: importing a package registers its views on its blueprint
    import app.feeds
    import app.help
    import app.analysis
    import app.events
    import app.remediation
    import app.file_collection

    flask_app.register_blueprint(main)
    flask_app.register_blueprint(auth)
    flask_app.register_blueprint(admin)
    flask_app.register_blueprint(signatures)
    flask_app.register_blueprint(svs)
    flask_app.register_blueprint(feeds)
    flask_app.register_blueprint(help_pages)
    flask_app.register_blueprint(analysis)
    flask_app.register_blueprint(events)
    flask_app.register_blueprint(remediation)
    flask_app.register_blueprint(file_collection)