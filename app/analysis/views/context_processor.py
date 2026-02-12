from uuid import uuid4
from app.blueprints import analysis

# additional functions to make available to the templates
@analysis.context_processor
def generic_functions():
    def generate_unique_reference():
        return str(uuid4())

    return { 'generate_unique_reference': generate_unique_reference }

@analysis.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response