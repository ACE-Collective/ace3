"""Utility for calling async code from synchronous Flask views."""

import asyncio
import threading
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

from aceapi_v2.database import get_async_session
from saq.database.pool import remove_all_sessions

T = TypeVar("T")

# Persistent event loop running in a background thread. This ensures that
# the cached async engine and its connection pool stay bound to a single
# loop across all synchronous calls.
_loop: asyncio.AbstractEventLoop | None = None
_loop_lock = threading.Lock()


def _get_loop() -> asyncio.AbstractEventLoop:
    """Return the shared background event loop, starting it if needed."""
    global _loop
    if _loop is None or _loop.is_closed():
        with _loop_lock:
            if _loop is None or _loop.is_closed():
                _loop = asyncio.new_event_loop()
                thread = threading.Thread(target=_loop.run_forever, daemon=True)
                thread.start()
    return _loop


async def run_db_in_thread(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a sync get_db()-using function in a worker thread, resetting the
    thread-local session afterward."""
    def _wrapped() -> T:
        try:
            return fn(*args, **kwargs)
        finally:
            remove_all_sessions()

    return await asyncio.to_thread(_wrapped)


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """Run an async coroutine from synchronous code.

    Submits the coroutine to a persistent background event loop and blocks
    until the result is available. This keeps the async engine's connection
    pool bound to a single loop across calls.
    """
    future = asyncio.run_coroutine_threadsafe(coro, _get_loop())
    return future.result()


def run_async_with_session(fn: Callable[..., Coroutine[Any, Any, T]], *args: Any, **kwargs: Any) -> T:
    """Call an async service function with an auto-acquired async database session.

    The first argument passed to *fn* will be an AsyncSession obtained from
    get_async_session(); any extra positional/keyword args follow it.

    The get_async_session() generator commits on its normal-exit path and rolls back on error, so
    the generator must be driven to completion for writes to persist -- returning out of an
    ``async for`` mid-iteration would leave the commit unrun. We therefore resume the generator after
    the call (success -> commit) or throw into it (error -> rollback).

    Usage from Flask views::

        from aceapi_v2.sync import run_async_with_session
        from aceapi_v2.threat_types.service import get_threat_types

        threat_types = run_async_with_session(get_threat_types)
    """
    async def _run():
        agen = get_async_session()
        session = await agen.__anext__()
        try:
            result = await fn(session, *args, **kwargs)
        except BaseException as exc:
            # drive the generator's error path (rollback) and propagate the original exception
            try:
                await agen.athrow(exc)
            except StopAsyncIteration:
                pass
            raise
        # drive the generator's success path (commit)
        try:
            await agen.__anext__()
        except StopAsyncIteration:
            pass
        return result

    return run_async(_run())
