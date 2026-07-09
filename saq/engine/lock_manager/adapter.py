from typing import Callable, Optional

from saq.engine.lock_manager.distributed import DistributedLockManager
from saq.engine.lock_manager.interface import LockManagerInterface

class LockManagerAdapter(LockManagerInterface):
    """Adapter that provides the LockManagerInterface interface using any LockManagerInterface implementation."""
    
    def __init__(self, 
                 lock_manager: Optional[LockManagerInterface] = None,
                 lock_uuid: Optional[str] = None, 
                 lock_owner: Optional[str] = None):
        """Initialize the adapter with a lock manager instance.
        
        Args:
            lock_manager: The lock manager instance to use. If None, a DistributedLockManager will be created.
            lock_uuid: UUID to use for locking operations (only used if lock_manager is None). If None, one will be generated.
            lock_owner: Description of the lock owner for tracking purposes (only used if lock_manager is None). If None, one will be generated.
        """
        if lock_manager is not None:
            self._lock_manager = lock_manager
        else:
            self._lock_manager = DistributedLockManager(lock_uuid=lock_uuid, lock_owner=lock_owner)
    
    def start_keepalive(self, target_uuid: str, on_lock_lost: Optional[Callable[[], None]] = None) -> bool:
        """Start the keepalive thread for the given target UUID."""
        return self._lock_manager.start_keepalive(target_uuid, on_lock_lost=on_lock_lost)

    def stop_keepalive(self) -> None:
        """Stop the keepalive thread and release the current lock."""
        self._lock_manager.stop_keepalive()

    def acquire_lock(self, target_uuid: str, allow_expired_takeover: bool = False) -> bool:
        """Acquire a lock on the given target UUID."""
        return self._lock_manager.acquire_lock(target_uuid, allow_expired_takeover=allow_expired_takeover)

    def release_lock(self, target_uuid: str, ignore_lock_failure: bool = False) -> bool:
        """Release a lock on the given target UUID."""
        return self._lock_manager.release_lock(target_uuid, ignore_lock_failure)

    def force_release_lock(self, target_uuid: str, lock_uuid: Optional[str] = None) -> bool:
        """Force release a lock on the given target UUID."""
        return self._lock_manager.force_release_lock(target_uuid, lock_uuid=lock_uuid)

    @property
    def is_lock_lost(self) -> bool:
        """Returns True if the keepalive detected the lock was lost to another owner."""
        return getattr(self._lock_manager, "is_lock_lost", False)

    @property
    def is_keepalive_active(self) -> bool:
        """Returns True if the keepalive thread is currently running."""
        return self._lock_manager.is_keepalive_active
        
    @property
    def current_lock_target(self) -> Optional[str]:
        """Returns the UUID of the currently locked target, if any."""
        return self._lock_manager.current_lock_target
        
    @property
    def lock_uuid(self) -> str:
        """Returns the UUID used for locking operations."""
        return self._lock_manager.lock_uuid 

    @property
    def lock_owner(self) -> str:
        """Returns an identifier for the owner of the lock."""
        return self._lock_manager.lock_owner 