from flask import Blueprint, Flask

# only the GUI shows observable actions, and only the GUI imports this module, so the action is
# registered here rather than in the package init every process imports
import example.app.observable_actions  # noqa: F401

# GUI pages and the templates of the observable action; what a page or an action fetches comes
# from the API routes (example/api/router.py)
example_bp = Blueprint('example', __name__, url_prefix='/example', template_folder="../templates")


def register(flask_app: Flask) -> None:
    """Registers the GUI pages. The GUI calls this from gui_blueprint in etc/saq.integration.yaml."""
    # imported here because example.app.views imports example_bp from this module; importing it is what
    # adds its routes to the blueprint
    import example.app.views  # noqa: F401
    flask_app.register_blueprint(example_bp)
