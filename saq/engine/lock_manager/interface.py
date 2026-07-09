from abc import ABC, abstractmethod
from typing import Callable, Optional


class LockManagerInterface(ABC):
    """Interface for distributed lock managers."""

    @abstractmethod
    def start_keepalive(self, target_uuid: str, on_lock_lost: Optional[Callable[[], None]] = None) -> bool:
        """Start the keepalive thread for the given target UUID.

        Args:
            target_uuid: The UUID of the resource to maintain a lock on.
            on_lock_lost: optional callback invoked (from the keepalive thread) if the lock can no
                longer be maintained -- used to abort the in-flight analysis.

        Returns:
            True if the keepalive was started successfully, False otherwise.
        """
        pass

    @abstractmethod
    def stop_keepalive(self) -> None:
        """Stop the keepalive thread. Does not release the lock; the caller (e.g. workload manager) owns release."""
        pass

    @abstractmethod
    def acquire_lock(self, target_uuid: str, allow_expired_takeover: bool = False) -> bool:
        """Acquire a lock on the given target UUID.

        Args:
            target_uuid: The UUID of the resource to lock.
            allow_expired_takeover: when True, permit taking over an expired lock held by another
                owner. Only manager-owned recovery paths may set this; workers must not.

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
    def force_release_lock(self, target_uuid: str, lock_uuid: Optional[str] = None) -> bool:
        """Force release a lock on the given target UUID.

        Args:
            target_uuid: The UUID of the resource to unlock.
            lock_uuid: when provided, only release the lock if it still matches this specific
                lock_uuid (ownership-aware); when None, release unconditionally (legacy).

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