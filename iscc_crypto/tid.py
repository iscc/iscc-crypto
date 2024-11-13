"""
ISCC Time-ID

This module provides high-precision, monotonic timestamp generation for distributed systems.
It ensures system-wide unique timestamps with microsecond granularity that can be safely
used across threads and processes.

Key features:
- Microsecond (μs) precision timestamps since Unix epoch
- Strictly monotonic (always increasing) sequence guarantee
- Thread-safe and multiprocessing-safe implementation
- Both synchronous and asynchronous interfaces
- Upper-bounded by system time (never runs ahead)
- Cross-platform compatible pure Python implementation
- Minimal CPU usage through adaptive sleep

Warning:
    The current implementation is sufficient for most use cases where processes are spawned
    programmatically from a common parent process, but won't guarantee monotonicity across
    independently started Python processes.

Note:
    The implementation is optimized within the constraints of pure-Python timing
    resolution. For details on these constraints see:
    https://stackoverflow.com/q/1133857/51627

Usage:
    >>> from iscc_crypto.tid import microtime
    >>> ts = microtime()  # Returns microseconds since epoch as integer
"""

import time
import asyncio
import multiprocessing as mp
from ctypes import c_longlong
from rich import print


# Shared timestamp using multiprocessing.Value
_LAST_TS = mp.Value(c_longlong, 0)


def microtime():
    # type: () -> int
    """
    Generate unique monotonic microsecond timestamps.

    Thread and process safe timestamp generator that blocks minimally when
    system clock resolution is exceeded.

    :return: Microseconds since Unix epoch as monotonically increasing integer
    """
    with _LAST_TS.get_lock():
        while True:
            real_time = time.time_ns() // 1_000
            if real_time > _LAST_TS.value:
                _LAST_TS.value = real_time
                return real_time
            else:
                # Sleep briefly to prevent high CPU usage
                time.sleep(1e-7)  # Sleep 0.1 microsecond


async def amicrotime():
    # type: () -> int
    """
    Async wrapper for microtime() that runs in thread executor.

    :return: Microseconds since Unix epoch as monotonically increasing integer
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, microtime)


if __name__ == "__main__":
    print("Sync timestamp:", microtime())

    async def run_async():
        print("Async timestamp:", await amicrotime())

    asyncio.run(run_async())
