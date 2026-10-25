from flask import Blueprint

# GUI pages and the templates of the observable action; what a page or an action fetches comes
# from the API routes (example/api/router.py)
example_bp = Blueprint('example', __name__, url_prefix='/example', template_folder="../templates")
