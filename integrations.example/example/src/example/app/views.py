from flask import render_template
from example.app.blueprint import example_bp

@example_bp.route('/', methods=['GET', 'POST'])
def index():
    return render_template('example/index.html')
