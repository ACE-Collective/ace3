# deliberately imports nothing: integrations import app.integration from every ACE process to register
# their blueprints, and anything imported here would load the whole GUI into each of those processes.
# The application is app.application.create_app().
