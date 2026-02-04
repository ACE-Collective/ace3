"""Utility for calling async code from synchronous Flask views."""

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar

T = TypeVar("T")


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """Run an async coroutine from synchronous code.

    Uses asyncio.run() to execute the coroutine in a new event loop.
    Intended for use in Flask views that need to call async service functions.
    """
    return asyncio.run(coro)
