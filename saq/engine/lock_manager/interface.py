from abc import ABC, abstractmethod
from typing import Optional


class LockManagerInterface(ABC):
    """Interface for distributed lock managers."""
    
    @abstractmethod
    def start_keepalive(self, target_uuid: str) -> bool:
        """Start the keepalive thread for the given target UUID.
        
        Args:
            target_uuid: The UUID of the resource to maintain a lock on.
            
        Returns:
            True if the keepalive was started successfully, False otherwise.
        """
        pass
        
    @abstractmethod
    def stop_keepalive(self) -> None:
        """Stop the keepalive thread. Does not release the lock; the caller (e.g. workload manager) owns release."""
        pass
        
    @abstractmethod
    def acquire_lock(self, target_uuid: str) -> bool:
        """Acquire a lock on the given target UUID.
        
        Args:
            target_uuid: The UUID of the resource to lock.
            
        Returns:
            True if the lock was acquired, False otherwise.
        """
        pass
        
    @abstractmethod
    def release_lock(self, target_uuid: str, ignore_lock_failure: bool = False) -> bool:
        """Release a lock on the given target UUID.
        
        Args:
            target_uuid: The UUID of the resource to unlock.
            
        Returns:
            True if the lock was released, False otherwise.
        """
        pass

    @abstractmethod
    def force_release_lock(self, target_uuid: str) -> bool:
        """Force release a lock on the given target UUID.
        
        Args:
            target_uuid: The UUID of the resource to unlock.
            
        Returns:
            True if the lock was released, False otherwise.
        """
        pass
        
    @property
    @abstractmethod
    def is_keepalive_active(self) -> bool:
        """Returns True if the keepalive thread is currently running."""
        pass
        
    @property
    @abstractmethod
    def current_lock_target(self) -> Optional[str]:
        """Returns the UUID of the currently locked target, if any."""
        pass
        
    @property
    @abstractmethod
    def lock_uuid(self) -> str:
        """Returns the UUID used for locking operations."""
        pass

    @property
    @abstractmethod
    def lock_owner(self) -> str:
        """Returns an identifier for the owner of the lock."""
        pass