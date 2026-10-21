"""File change notification system for monitoring file modifications.

This module provides functionality to watch files for changes and execute callbacks
when modifications are detected.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Callable, Dict, Optional

from saq.configuration.config import get_config


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
                if not os.path.exists(watched_file.path):
                    continue
                
                current_mtime = os.stat(watched_file.path).st_mtime
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
