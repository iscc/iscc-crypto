"""
Atomic System-Wide Timestamps

Provides high-precision, monotonic timestamp generation for distributed systems with
nanosecond precision. Ensures system-wide unique timestamps that can be safely
used across threads and independent processes.

Features:
- Nanosecond source time precision
- Strictly monotonic (always increasing) sequence guarantee
- Thread-safe and multiprocessing-safe across independent processes
- Prevents system time front-running
- Cross-platform compatible
"""

import time
import asyncio
import atexit
import getpass
import uuid
from multiprocessing import shared_memory
import atomics
from loguru import logger as log


# Module constants
RESOLUTION = 1e-5
WAIT = RESOLUTION
NANOS_PER_UNIT = int(RESOLUTION * 1e9)


def _init_shared_memory():
    # type: () -> tuple[shared_memory.SharedMemory, atomics.atomic]
    """Initialize shared memory and atomic counter for timestamp generation."""
    user = getpass.getuser()
    unique_name = f"timestamp-{user}-{uuid.getnode()}"

    try:
        # Create or connect to shared memory
        shm = shared_memory.SharedMemory(name=unique_name, create=True, size=8)
        counter = atomics.atomic(width=8, atype=atomics.UINT, buffer=shm.buf)
        initial_time = time.time_ns() // NANOS_PER_UNIT
        counter.store(initial_time)
        log.debug(f"Created new shared memory {unique_name}")
        return shm, counter

    except FileExistsError:
        shm = shared_memory.SharedMemory(name=unique_name, create=False)
        counter = atomics.atomic(width=8, atype=atomics.UINT, buffer=shm.buf)
        log.debug(f"Connected to existing shared memory {unique_name}")
        return shm, counter


# Initialize shared memory at module load time
_SHM, _COUNTER = _init_shared_memory()
atexit.register(lambda: (_SHM.close(), _SHM.unlink()))


def timestamp(max_attempts=1000):
    # type: (int) -> int
    """
    Generate unique monotonic timestamps.

    System-wide atomic timestamp generator that prevents front-running and ensures
    strictly monotonic sequence. Uses shared memory for cross-process synchronization.

    :param max_attempts: Maximum number of attempts before raising RuntimeError
    :return: Timestamp as integer units since epoch at configured resolution
    :raises RuntimeError: If atomic operations fail repeatedly
    """
    for _ in range(max_attempts):
        real_time = time.time_ns() // NANOS_PER_UNIT
        current = _COUNTER.load()

        # Never return a value greater than real time
        if current >= real_time:
            time.sleep(WAIT)
            continue

        # Try to set counter to real_time
        if _COUNTER.cmpxchg_strong(expected=current, desired=real_time).success:
            return real_time

    raise RuntimeError("Failed to generate monotonic timestamp")


async def atimestamp():
    # type: () -> int
    """
    Async wrapper for timestamp() that runs in thread executor.

    :return: Timestamp as integer units since epoch at configured resolution
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, timestamp)


if __name__ == "__main__":
    print(f"Timestamp: {timestamp()}")
