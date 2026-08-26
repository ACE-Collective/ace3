from flask import request, session
from flask_login import login_required
from app.blueprints import analysis

@analysis.route('/search', methods=['POST'])
@login_required
def search():
    # POST-only: this endpoint mutates session state.
    session["search"] = request.form.get("search", None)
    # return empy page
    return ('', 204)
