"""File change notification system for monitoring file modifications.

This module provides functionality to watch files for changes and execute callbacks
when modifications are detected.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Callable, Dict, Generic, Optional, TypeVar

import yaml
from pydantic import BaseModel

from saq.configuration.config import get_config
from saq.util.filesystem import abs_path

SettingsModel = TypeVar("SettingsModel", bound=BaseModel)


class WatchedFile:
    """Represents a file being watched for changes."""
    
    def __init__(self, path: str, callback: Callable[[], None]):
        """Initialize a watched file.
        
        Args:
            path: The file path to watch
            callback: The function to call when the file changes
        """
        self.path = path
        self.callback = callback
        self.last_mtime = 0
        # reported once per disappearance, not on every check
        self.missing_reported = False


class WatchedSettings(Generic[SettingsModel]):
    """An analyst-editable YAML settings file, validated with a pydantic model and reloaded when it
    changes. ``value`` is the last version of the file that validated, or the model's defaults
    until one has: a bad edit is logged and rejected whole rather than undoing the tuning already
    in effect. A blank path never watches anything and stays on the defaults."""

    def __init__(self, watcher: "FileWatcher", path: str, model_class: type[SettingsModel]):
        self.path = abs_path(path) if path else None
        self.model_class = model_class
        self._watcher = watcher
        self._watched = False
        self._value = model_class()

    @property
    def value(self) -> SettingsModel:
        # loaded on first use, so a worker that builds the module but never runs it never reads the file
        if not self._watched and self.path:
            self._watched = True
            # loads the file now, and again whenever it changes
            self._watcher.watch_file(self.path, self.reload)

        return self._value

    def reload(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fp:
                value = self.model_class.model_validate(yaml.safe_load(fp) or {})
        except Exception:
            logging.exception(f"unable to load settings file {self.path}; the settings already in effect are kept",
                              extra={"path": self.path})
            return

        self._value = value
        logging.info(f"loaded settings file {self.path}", extra={"path": self.path})


class FileWatcher:
    """A file watching system that monitors files for changes and executes callbacks."""
    
    def __init__(self):
        """Initialize the file watcher."""
        self.watched_files: Dict[str, WatchedFile] = {}
        self.next_check_watched_files: Optional[datetime] = None
    
    def watch_file(self, path: str, callback: Callable[[], None]) -> None:
        """Watch the given file and execute callback when it detects that the file has been modified.
        
        Args:
            path: The file path to watch
            callback: The function to call when the file is modified
        """
        if path in self.watched_files:
            logging.warning("replacing callback {} for {} with {}".format(
                self.watched_files[path].callback, path, callback))
        
        logging.debug("watching file {}".format(path))
        self.watched_files[path] = WatchedFile(path, callback)
        
        # Go ahead and load it up - reset the check timer to force immediate check
        self.next_check_watched_files = None
        self.check_watched_files()

    def watch_settings(self, path: str, model_class: type[SettingsModel]) -> WatchedSettings[SettingsModel]:
        """Watch an analyst-editable YAML settings file (see WatchedSettings). ``path`` is relative to
        SAQ_HOME unless absolute. Nothing is read until ``value`` is first used."""
        return WatchedSettings(self, path, model_class)
    
    def unwatch_file(self, path: str) -> bool:
        """Stop watching a file.
        
        Args:
            path: The file path to stop watching
            
        Returns:
            True if the file was being watched and is now unwatched, False otherwise
        """
        if path in self.watched_files:
            del self.watched_files[path]
            logging.debug("stopped watching file {}".format(path))
            return True
        return False
    
    def check_watched_files(self) -> None:
        """Check all watched files for changes and execute callbacks if modifications are detected."""
        # Is it time to check the files we're watching?
        if self.next_check_watched_files is not None and datetime.now() < self.next_check_watched_files:
            return
        
        # Check every N seconds (as configured)
        check_frequency = get_config().global_settings.check_watched_files_frequency
        self.next_check_watched_files = datetime.now() + timedelta(seconds=check_frequency)
        
        for watched_file in self.watched_files.values():
            try:
                try:
                    current_mtime = os.stat(watched_file.path).st_mtime
                except OSError:
                    # whatever reads the file keeps running on what it last loaded, so say so once
                    if not watched_file.missing_reported:
                        watched_file.missing_reported = True
                        logging.exception(f"watched file {watched_file.path} does not exist or cannot be read; "
                                          "whatever reads it keeps the version it last loaded, or its defaults",
                                          extra={"path": watched_file.path})
                    # a file put back with the mtime it had before it went away (cp -p, a restore from
                    # backup) is still a change
                    watched_file.last_mtime = 0
                    continue

                watched_file.missing_reported = False
                if watched_file.last_mtime != current_mtime:
                    logging.info("detected change to {}".format(watched_file.path))
                    
                    watched_file.last_mtime = current_mtime
                    
                    try:
                        watched_file.callback()
                    except Exception as e:
                        logging.exception("callback failed for watched file {}: {}".format(watched_file.path, e))
            
            except Exception as e:
                logging.exception("unable to check file {}: {}".format(watched_file.path, e))
    
    def clear_all_watched_files(self) -> None:
        """Stop watching all files."""
        self.watched_files.clear()
        self.next_check_watched_files = None
        logging.debug("cleared all watched files")
    
    def get_watched_files(self) -> Dict[str, str]:
        """Get a mapping of watched file paths to their callback function names.
        
        Returns:
            Dictionary mapping file paths to callback function names
        """
        return {path: watched_file.callback.__name__ if hasattr(watched_file.callback, '__name__') else str(watched_file.callback)
                for path, watched_file in self.watched_files.items()}


class FileWatcherMixin:
    """Mixin class that provides file watching capabilities."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # file watcher for monitoring file changes
        # NOTE that the file watcher is tied to the lifetime of the object
        self._file_watcher = FileWatcher()

    def watch_file(self, path, callback):
        """Watches the given file and executes callback when it detects that the file has been modified."""
        self._file_watcher.watch_file(path, callback)

    def watch_settings(self, path: str, model_class: type[SettingsModel]) -> WatchedSettings[SettingsModel]:
        """Watch an analyst-editable YAML settings file; see FileWatcher.watch_settings."""
        return self._file_watcher.watch_settings(path, model_class)

    def check_watched_files(self):
        """Check watched files for changes."""
        self._file_watcher.check_watched_files()

    def unwatch_file(self, path):
        """Stop watching a file."""
        return self._file_watcher.unwatch_file(path)

    @property
    def watched_files(self):
        """Get the currently watched files (for backward compatibility)."""
        return self._file_watcher.get_watched_files()
