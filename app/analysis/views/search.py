from flask import request, session
from flask_login import login_required
from app.blueprints import analysis

@analysis.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    session["search"] = request.values.get("search", None)
    # return empy page
    return ('', 204)
