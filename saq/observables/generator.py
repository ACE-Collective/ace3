from datetime import datetime
import importlib
import logging
from typing import Optional, Type, Union

from saq.analysis.observable import Observable
from saq.analysis.serialize.observable_serializer import KEY_TYPE
from saq.configuration.config import get_config
from saq.observables.base import DefaultObservable, ObservableValueError

# keyed by the module:Class target rather than by the type, so a configuration that maps a type to
# another class is never answered with the class it used to map to
_LOADED_CLASSES: dict[str, Type[Observable]] = {}

def get_observable_class(o_type: str) -> Optional[Type[Observable]]:
    """Returns the class configured for the observable type in observable_types.classes, importing its
    module the first time, or None when the type has none."""
    target = get_config().observable_types.classes.get(o_type)
    if target is None:
        return None

    o_class = _LOADED_CLASSES.get(target)
    if o_class is not None:
        return o_class

    module_name, class_name = target.split(":")
    try:
        o_class = getattr(importlib.import_module(module_name), class_name)
    except (ImportError, AttributeError) as e:
        # an observable of this type cannot be built or loaded as anything else: a DefaultObservable
        # would drop what the class keeps when the root is saved again
        raise ImportError(f"observable_types.classes.{o_type}: cannot load {target}: {e}") from e

    _LOADED_CLASSES[target] = o_class
    return o_class

def create_observable(o_type: str, o_value: str, o_time: Union[str, datetime, None]=None, sort_order: int=100, volatile: bool=False) -> Optional[Observable]:
    """This creates a new Observable instance with the given parameters. Returns None if the parameters are invalid for th given type."""

    o_class = get_observable_class(o_type)

    try:
        # because DefaultObservable takes a different set of arguments than the other observables...
        if o_class is None:
            return DefaultObservable(o_type, o_value, time=o_time, sort_order=sort_order, volatile=volatile)
        else:
            # otherwise it takes the default set of arguments
            return o_class(o_value, time=o_time, sort_order=sort_order, volatile=volatile)
    except ObservableValueError as e:
        logging.debug("invalid value {} for observable type {}: {}".format(o_value.encode('unicode_escape'), o_type, e))
        return None

def create_observable_from_dict(o_dict: dict) -> Optional[Observable]:
    """Creates an Observable instance from the given dictionary. Returns None if the dictionary is invalid."""
    o_type = o_dict[KEY_TYPE]
    o_class = get_observable_class(o_type) or DefaultObservable
    return o_class.from_json(o_dict)
