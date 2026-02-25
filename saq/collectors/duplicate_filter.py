import logging
import time
from datetime import timedelta
from typing import Optional
from ace_api import sha256_str
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.persistence import Persistable


class DuplicateSubmissionFilter():
    """Manages persistence logic for preventing duplicate submissions."""
    
    # TODO: service config needs to be abstracted
    def __init__(self, persistence_manager: Persistable, service_config: CollectorServiceConfiguration):
        """Initialize the duplicate submission filter.
        
        Args:
            service_name: The name of the service for persistence source registration
            service_config: Configuration dictionary for persistence settings
        """
        if not persistence_manager.persistence_source:
            raise RuntimeError("persistence_manager.persistence_source is not set")
        
        self.persistence_manager = persistence_manager
        self.service_config = service_config
        self.persistent_clear_time = time.time()
    
    def is_duplicate(self, key: str) -> bool:
        """Check if a submission key is a duplicate.
        
        Args:
            key: The submission key to check
            
        Returns:
            bool: True if the key is a duplicate, False otherwise
        """
        if not key:
            return False
            
        key_hash = sha256_str(key)
        return self.persistence_manager.persistent_data_exists(key_hash)
    
    def mark_as_processed(self, key: str) -> None:
        """Mark a submission key as processed.
        
        Args:
            key: The submission key to mark as processed
        """
        if not key:
            return
            
        key_hash = sha256_str(key)
        self.persistence_manager.save_persistent_key(key_hash)
    
    def clear_expired_data(self) -> None:
        """Clear expired persistent data based on configured timeouts."""
        # Only do this every so often
        clear_interval = self.service_config.persistence_clear_seconds
        if time.time() - self.persistent_clear_time > clear_interval:
            
            expiration_seconds = self.service_config.persistence_expiration_seconds
            unmodified_expiration_seconds = self.service_config.persistence_unmodified_expiration_seconds
            
            expiration_timedelta = timedelta(seconds=expiration_seconds)
            unmodified_expiration_timedelta = timedelta(seconds=unmodified_expiration_seconds)

            try:
                # It's OK if this fails but we should be notified about it
                self.persistence_manager.delete_expired_persistent_keys(expiration_timedelta, unmodified_expiration_timedelta)
            except Exception as e:
                logging.warning("unable to delete expired persistent keys: %s", e)

            self.persistent_clear_time = time.time() 