import logging
import os
import threading
import uuid
from typing import Optional

from saq.configuration.config import get_config
from saq.database.util.locking import acquire_lock, force_release_lock, release_lock
from saq.engine.lock_manager.interface import LockManagerInterface
from saq.error import report_exception

class DistributedLockManager(LockManagerInterface):
    """Manages distributed locks with automatic keepalive functionality."""
    
    def __init__(self, lock_uuid: Optional[str] = None, lock_owner: Optional[str] = None):
        """Initialize the lock manager.
        
        Args:
            lock_uuid: UUID to use for locking operations. If None, one will be generated.
            lock_owner: Description of the lock owner for tracking purposes. If None, one will be generated.
        """
        self._lock_uuid = lock_uuid or str(uuid.uuid4())
        self._lock_owner = lock_owner or "{}-{}".format(os.getpid(), self.lock_uuid)
        
        # Threading control for keepalive
        self._control_event: Optional[threading.Event] = None
        self._keepalive_thread: Optional[threading.Thread] = None
        self._current_lock_target: Optional[str] = None

    @property
    def lock_uuid(self) -> str:
        """Returns the UUID used for locking operations."""
        return self._lock_uuid

    @property
    def lock_owner(self) -> str:
        """Returns an identifier for the owner of the lock."""
        return self._lock_owner
        
    def start_keepalive(self, target_uuid: str) -> bool:
        """Start the keepalive thread for the given target UUID.
        
        Args:
            target_uuid: The UUID of the resource to maintain a lock on.
            
        Returns:
            True if the keepalive was started successfully, False otherwise.
        """
        if self._keepalive_thread is not None:
            logging.warning("Keepalive thread already running for a different target")
            return False
            
        if not acquire_lock(target_uuid, self.lock_uuid, lock_owner=self.lock_owner):
            logging.warning(f"Failed to acquire initial lock on {target_uuid}")
            return False
            
        logging.debug(f"Starting lock keepalive for {target_uuid}")
        
        self._current_lock_target = target_uuid
        self._control_event = threading.Event()
        
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            name=f"Lock Manager ({target_uuid})",
            args=(target_uuid,),
            daemon=True
        )
        self._keepalive_thread.start()
        
        return True
        
    def stop_keepalive(self) -> None:
        """Stop the keepalive thread. Does not release the lock; the caller (e.g. workload manager) owns release."""
        if self._control_event is None:
            logging.debug("No keepalive thread running")
            return
            
        logging.debug(f"Stopping lock keepalive for {self._current_lock_target}")
        
        self._control_event.set()
        
        if self._keepalive_thread and self._keepalive_thread.is_alive():
            self._keepalive_thread.join()
            
        # Clean up thread state only; do not release the lock (workload manager owns release)
        self._control_event = None
        self._keepalive_thread = None
        self._current_lock_target = None
        
    def acquire_lock(self, target_uuid: str) -> bool:
        """Acquire a lock on the given target UUID.
        
        Args:
            target_uuid: The UUID of the resource to lock.
            
        Returns:
            True if the lock was acquired, False otherwise.
        """
        return acquire_lock(target_uuid, self.lock_uuid, lock_owner=self.lock_owner)

    def force_release_lock(self, target_uuid: str) -> bool:
        """Force release a lock on the given target UUID."""
        return force_release_lock(target_uuid)
        
    def release_lock(self, target_uuid: str, ignore_lock_failure: bool = False) -> bool:
        """Release a lock on the given target UUID.
        
        Args:
            target_uuid: The UUID of the resource to unlock.
            
        Returns:
            True if the lock was released, False otherwise.
        """
        return release_lock(target_uuid, self.lock_uuid, ignore_lock_failure)
        
    def _keepalive_loop(self, target_uuid: str) -> None:
        """Main loop for maintaining the lock on the target UUID."""
        try:
            keepalive_frequency = float(
                get_config().global_settings.lock_keepalive_frequency
            )
            
            while not self._control_event.is_set():
                if self._control_event.wait(keepalive_frequency):
                    break
                    
                if not acquire_lock(target_uuid, self.lock_uuid, lock_owner=self.lock_owner):
                    logging.warning(f"Failed to maintain lock on {target_uuid}")
                    break
                    
        except Exception as e:
            logging.error(f"Unexpected error in keepalive loop for {target_uuid}: {e}")
            report_exception()
            
        logging.debug(f"Lock keepalive for {target_uuid} exited")
        
    @property
    def is_keepalive_active(self) -> bool:
        """Returns True if the keepalive thread is currently running."""
        return (
            self._keepalive_thread is not None 
            and self._keepalive_thread.is_alive()
        )
        
    @property
    def current_lock_target(self) -> Optional[str]:
        """Returns the UUID of the currently locked target, if any."""
        return self._current_lock_target 