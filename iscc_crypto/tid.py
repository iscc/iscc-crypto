"""
ISCC Time-ID

This module provides high-precision, monotonic timestamp generation for distributed systems.
It ensures system-wide unique timestamps with microsecond granularity that can be safely
used across threads and processes.

Key Requirements:
- Microsecond (μs) precision timestamps since Unix epoch
- Strictly monotonic (always increasing) sequence guarantee
- Thread-safe and multiprocessing-safe implementation across independent processes
- Both synchronous and asynchronous interfaces
- Upper-bounded by system time (never runs ahead)
- Cross-platform compatible support
- Minimal CPU usage

Note:
    The implementation is optimized within the constraints of OS-level `sleep` resolution.
    For details on these constraints see:
    https://stackoverflow.com/q/1133857/51627

Usage:
    >>> from iscc_crypto.tid import microtime
    >>> ts = microtime()  # Returns microseconds since epoch as integer
"""

import time
import asyncio
from multiprocessing import shared_memory
import atomics
import getpass
import uuid
import atexit

# Create a unique shared memory name
user = getpass.getuser()
unique_name = f"tid-{user}-{uuid.getnode()}"

# Create or connect to shared memory for atomic timestamp
try:
    _SHM = shared_memory.SharedMemory(name=unique_name, create=True, size=8)
    _LAST_TS = atomics.atomic(width=8, atype=atomics.INT, buffer=_SHM.buf)
    _LAST_TS.store(time.time_ns() // 1_000)  # Initialize to current time in microseconds
except FileExistsError:
    _SHM = shared_memory.SharedMemory(name=unique_name, create=False)
    _LAST_TS = atomics.atomic(width=8, atype=atomics.INT, buffer=_SHM.buf)
except PermissionError as e:
    raise PermissionError(f"Cannot create or access shared memory: {e}")


# Ensure shared memory is cleaned up on exit
def cleanup_shared_memory():
    _SHM.close()
    try:
        _SHM.unlink()
    except FileNotFoundError:
        pass  # Already unlinked


atexit.register(cleanup_shared_memory)


def microtime():
    # type: () -> int
    """
    Generate unique monotonic microsecond timestamps.

    System-wide atomic timestamp generator that blocks minimally when
    system clock resolution is exceeded. Uses shared memory for cross-process
    synchronization.

    :return: Microseconds since Unix epoch as monotonically increasing integer
    """
    while True:
        current = _LAST_TS.load()
        # Try incrementing first as it's likely the most common case
        next_ts = current + 1
        real_time = time.time_ns() // 1_000

        if next_ts <= real_time:
            # Try to increment the current value
            res = _LAST_TS.cmpxchg_strong(expected=current, desired=next_ts)
            if res.success:
                return next_ts
        elif real_time > current:
            # Real time jumped ahead, use that instead
            res = _LAST_TS.cmpxchg_strong(expected=current, desired=real_time)
            if res.success:
                return real_time
        else:
            # Sleep briefly to prevent high CPU usage
            time.sleep(1e-6)  # Sleep 1 microsecond


async def amicrotime():
    # type: () -> int
    """
    Async wrapper for microtime() that runs in thread executor.

    :return: Microseconds since Unix epoch as monotonically increasing integer
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, microtime)


if __name__ == "__main__":
    print("Sync timestamp:", microtime())

    async def run_async():
        print("Async timestamp:", await amicrotime())

    asyncio.run(run_async())
