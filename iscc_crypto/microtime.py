"""
# Microtime - System-Wide Microsecond Timestamps

This module provides high-precision, monotonic timestamp generation for distributed systems.
It ensures system-wide unique timestamps with microsecond granularity that can be safely
used across threads and independent processes.

## Key Features

- Microsecond (μs) precision timestamps since Unix epoch
- Strictly monotonic (always increasing) sequence guarantee
- Thread-safe and multiprocessing-safe implementation across independent processes
- Both synchronous and asynchronous interfaces
- Upper-bounded by system time (never runs ahead)
- Cross-platform compatible support

## Implementation Details

- Uses shared memory for cross-process synchronization
- Atomic operations ensure thread safety
- Busy-wait with minimal sleep when system clock resolution is exceeded
- Graceful cleanup of shared resources on process exit
- Handles system clock adjustments and jumps

## Warning

This module assumes your system clock is accurate and synchronized. You must separately
ensure proper time synchronization across your infrastructure. Best practices include:

- Use NTP with multiple reliable timeservers
- Configure chrony or similar for precise time sync:
  ```bash
  # /etc/chrony.conf
  pool pool.ntp.org iburst
  makestep 1.0 3    # Step clock if off by >1 sec for first 3 updates
  maxupdateskew 100.0
  ```
- Monitor clock drift and sync status:
  ```bash
  chronyc tracking  # Check sync status
  chronyc sources   # View time sources
  ```

## Performance

The implementation is optimized within the constraints of OS-specific `sleep` resolution.
For details on these constraints see: https://stackoverflow.com/q/1133857/51627

Usage:
    >>> from iscc_crypto.microtime import microtime
    >>> ts = microtime()  # Returns microseconds since epoch as integer
"""

import time
import asyncio
from multiprocessing import shared_memory
import atomics
import getpass
import uuid
import atexit
from loguru import logger as log

# Constants
MICROS_PER_SECOND = 1_000_000
NANOS_PER_MICRO = 1_000
MIN_SLEEP_MICROS = 1
MAX_TIMESTAMP = 2**63 - 1  # Max value for int64
MIN_TIMESTAMP = 0
SLEEP_TIME = MIN_SLEEP_MICROS / MICROS_PER_SECOND
MAX_ATTEMPTS = 1000


def _init_shared_memory():
    # type: () -> tuple[shared_memory.SharedMemory, atomics.atomic]
    """Initialize shared memory and atomic counter."""
    user = getpass.getuser()
    unique_name = f"microtime-{user}-{uuid.getnode()}"

    try:
        shm = shared_memory.SharedMemory(name=unique_name, create=True, size=8)
        counter = atomics.atomic(width=8, atype=atomics.UINT, buffer=shm.buf)
        initial_time = time.time_ns() // NANOS_PER_MICRO
        if not (MIN_TIMESTAMP <= initial_time <= MAX_TIMESTAMP):
            raise ValueError(f"Initial timestamp {initial_time} out of valid range")
        counter.store(initial_time)
        log.debug(f"Created new shared memory {unique_name}")
        return shm, counter
    except FileExistsError:
        shm = shared_memory.SharedMemory(name=unique_name, create=False)
        counter = atomics.atomic(width=8, atype=atomics.INT, buffer=shm.buf)
        log.debug(f"Connected to existing shared memory {unique_name}")
        return shm, counter
    except PermissionError as e:
        raise PermissionError(f"Cannot create or access shared memory: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to initialize shared memory: {e}")


# Initialize shared memory
_SHM, _LAST_TS = _init_shared_memory()


# Ensure shared memory is cleaned up on exit
def _cleanup_shared_memory():
    # type: () -> None
    """Clean up shared memory resources on process exit."""
    _SHM.close()
    try:
        _SHM.unlink()
        log.debug("Cleaned up shared memory")
    except FileNotFoundError:
        log.debug("Shared memory already unlinked")


atexit.register(_cleanup_shared_memory)


def microtime():
    # type: () -> int
    """
    Generate unique monotonic microsecond timestamps.

    System-wide atomic timestamp generator that blocks minimally when
    system clock resolution is exceeded. Uses shared memory for cross-process
    synchronization.

    Thread-safe and process-safe implementation that guarantees:
    - Strictly monotonic sequence (each value greater than the last)
    - Never returns a value greater than real system time
    - Microsecond precision within system capabilities
    - Minimal CPU usage when at clock resolution limits

    :return: Microseconds since Unix epoch as monotonically increasing integer
    :raises ValueError: If timestamp would exceed valid range
    :raises RuntimeError: If atomic operations fail repeatedly
    """
    attempts = 0

    while attempts < MAX_ATTEMPTS:
        current = _LAST_TS.load()
        if not (MIN_TIMESTAMP <= current <= MAX_TIMESTAMP):
            raise ValueError(f"Current timestamp {current} out of valid range")

        # Try incrementing first as it's likely the most common case
        next_ts = current + 1
        real_time = time.time_ns() // NANOS_PER_MICRO

        if next_ts <= real_time:
            # Try to increment the current value
            if not (MIN_TIMESTAMP <= next_ts <= MAX_TIMESTAMP):
                raise ValueError(f"Next timestamp {next_ts} out of valid range")
            res = _LAST_TS.cmpxchg_strong(expected=current, desired=next_ts)
            if res.success:
                return next_ts
        elif real_time > current:
            # Real time jumped ahead, use that instead
            if not (MIN_TIMESTAMP <= real_time <= MAX_TIMESTAMP):
                raise ValueError(f"Real timestamp {real_time} out of valid range")
            res = _LAST_TS.cmpxchg_strong(expected=current, desired=real_time)
            if res.success:
                return real_time
        else:
            # Sleep briefly to prevent high CPU usage
            time.sleep(SLEEP_TIME)

        attempts += 1

    raise RuntimeError("Failed to generate monotonic timestamp after maximum attempts")


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
