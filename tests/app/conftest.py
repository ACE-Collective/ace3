from flask import url_for
import pytest

from app.application import create_app
from saq.constants import QUEUE_DEFAULT
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission

@pytest.fixture(scope="function")
def analyst(global_setup):

    analyst = add_user(
        username="john",
        email="john@localhost",
        display_name="john",
        password="password",
        queue=QUEUE_DEFAULT,
        timezone="Etc/UTC"
    )

    # grant all permissions to the analyst
    add_user_permission(analyst.id, "*", "*")

    yield analyst.id

    delete_user("john")

@pytest.fixture(autouse=True, scope="function")
def app(global_setup):
    flask_app = create_app(testing=True)
    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,  # Disable CSRF for tests
    })

    app_context = flask_app.test_request_context()                      
    app_context.push()                           

    yield flask_app

@pytest.fixture
def web_client(app, analyst):
    with app.test_client() as client:
        login_result = client.post(url_for("auth.login"), data={
            "username": "john",
            "password": "password",
        })
        yield client
