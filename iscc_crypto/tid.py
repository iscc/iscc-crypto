"""
ISCC Time-ID

The module implements timestamp generation with the following properties:

- microsecond granularity
- strictly monotonic (unique) timestamps
- thread and multiprocessing safe
- sync and async implementations
- the timestamp generated never exceeds the current system time
- as performant as possible given pure-python, cross-platform, security and OS constraints

For time resolution constraints in pure-python see: https://stackoverflow.com/q/1133857/51627
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
    Integer timestamp in microseconds since epoch.

    A timestamp generator that can be called from multiple threads and/or processes to genarate
    system-wide unique (strictly monotoninc/increasing) timestamps. Timestamps are in microseconds
    since unix epoch based on the system clock. This function will block the current thread
    (time.sleep) until a new increasing microsecond is available. This may block for more than a
    microsecond due to the minimum resolution of `time.sleep` or  if system time is adjusted
    during runtime.
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
    """
    Async wrapper around the synchronous microtime() function using an executor.

    This method runs the blocking microtime() in a separate thread, avoiding
    blocking the event loop and improving performance.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, microtime)


if __name__ == "__main__":
    print("Sync timestamp:", microtime())

    async def run_async():
        print("Async timestamp:", await amicrotime())

    asyncio.run(run_async())
