from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask

_BLUEPRINT_CALLBACKS: list[Callable[["Flask"], None]] = []

def register_integration_blueprint_callback(callback: Callable):
    if callback not in _BLUEPRINT_CALLBACKS:
        _BLUEPRINT_CALLBACKS.append(callback)

def register_integration_blueprints(flask_app: "Flask"):
    for callback in _BLUEPRINT_CALLBACKS:
        callback(flask_app)
