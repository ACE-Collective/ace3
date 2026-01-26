# vim: sw=4:ts=4:et:cc=120

from app.file_collection.views.manage import manage
from app.file_collection.views.collections import collections
from app.file_collection.views.history import history

__all__ = ['manage', 'collections', 'history']
