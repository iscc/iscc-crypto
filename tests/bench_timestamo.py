from loguru import logger as log

log.remove()
from iscc_crypto.timestamp import timestamp, atimestamp, RESOLUTION
import time
import threading
import asyncio
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor
from queue import Queue


def _worker(duration, count_queue):
    """
    Worker function for threaded benchmark.

    :param duration: How long to run in seconds
    :param count_queue: Queue to report count back to main thread
    """
    count = 0
    end = time.time() + duration
    while time.time() < end:
        timestamp()
        count += 1
    count_queue.put(count)


def benchmark_tid_multithreaded(duration=10.0, num_threads=None):
    """
    Benchmark microtime() timestamp generation with multiple threads.

    :param duration: How long to run the benchmark in seconds
    :param num_threads: Number of threads to use (defaults to CPU count)
    :return: Total number of timestamps generated per second
    """
    if num_threads is None:
        num_threads = threading.active_count()

    count_queue = Queue()
    start = time.time()

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(_worker, duration, count_queue) for _ in range(num_threads)]

    total_count = sum(count_queue.get() for _ in range(num_threads))
    elapsed = time.time() - start
    rate = int(total_count / elapsed)
    print(f"Total rate: {rate:,} timestamps/second")
    return rate


def benchmark_tid(duration=10.0):
    """
    Benchmark microtime() timestamp generation for specified duration.

    :param duration: How long to run the benchmark in seconds
    :return: Number of timestamps generated per second
    """
    count = 0
    start = time.time()
    end = start + duration

    while time.time() < end:
        timestamp()
        count += 1

    elapsed = time.time() - start
    rate = int(count / elapsed)
    print(f"Total rate: {rate:,} timestamps/second")
    return rate


def _process_worker(duration, result_queue):
    """
    Worker function for multiprocess benchmark.

    :param duration: How long to run in seconds
    :param result_queue: Queue to report count back to main process
    """
    count = 0
    end = time.time() + duration
    while time.time() < end:
        timestamp()
        count += 1
    result_queue.put(count)


def benchmark_tid_multiprocessing(duration=10.0, num_processes=None):
    """
    Benchmark microtime() timestamp generation with multiple processes.

    :param duration: How long to run the benchmark in seconds
    :param num_processes: Number of processes to use (defaults to CPU count)
    :return: Total number of timestamps generated per second
    """
    if num_processes is None:
        num_processes = mp.cpu_count()

    result_queue = mp.Queue()
    start = time.time()

    processes = []
    for _ in range(num_processes):
        p = mp.Process(target=_process_worker, args=(duration, result_queue))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    total_count = sum(result_queue.get() for _ in range(num_processes))
    elapsed = time.time() - start
    rate = int(total_count / elapsed)
    print(f"Total rate: {rate:,} timestamps/second")
    return rate


def _thread_worker_for_process(duration, count_queue):
    """
    Thread worker function for combined process+thread benchmark.

    :param duration: How long to run in seconds
    :param count_queue: Queue to report count back to main process
    """
    count = 0
    end = time.time() + duration
    while time.time() < end:
        timestamp()
        count += 1
    count_queue.put(count)


def _process_worker_with_threads(duration, result_queue, num_threads):
    """
    Process worker that spawns multiple threads.

    :param duration: How long to run in seconds
    :param result_queue: Queue to report total count back to main process
    :param num_threads: Number of threads to spawn in this process
    """
    thread_queue = Queue()

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(_thread_worker_for_process, duration, thread_queue)
            for _ in range(num_threads)
        ]

    # Sum up counts from all threads in this process
    process_total = sum(thread_queue.get() for _ in range(num_threads))
    result_queue.put(process_total)


def benchmark_tid_multi_tm(duration=10.0, num_processes=None, num_threads=None):
    """
    Benchmark microtime() using multiple threads within multiple processes.

    :param duration: How long to run the benchmark in seconds
    :param num_processes: Number of processes to use (defaults to CPU count)
    :param num_threads: Number of threads per process (defaults to 2)
    :return: Total number of timestamps generated per second
    """
    if num_processes is None:
        num_processes = mp.cpu_count()
    if num_threads is None:
        num_threads = 2

    result_queue = mp.Queue()
    start = time.time()

    processes = []
    for _ in range(num_processes):
        p = mp.Process(
            target=_process_worker_with_threads, args=(duration, result_queue, num_threads)
        )
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    total_count = sum(result_queue.get() for _ in range(num_processes))
    elapsed = time.time() - start
    rate = int(total_count / elapsed)
    print(f"Total rate: {rate:,} timestamps/second")
    return rate


async def _async_worker(duration):
    """Single worker coroutine for async benchmark"""
    count = 0
    end = time.time() + duration
    while time.time() < end:
        await atimestamp()
        count += 1
    return count


async def _async_benchmark(duration):
    """
    Async helper function for benchmark_tid_async.

    :param duration: How long to run in seconds
    :return: Count of timestamps generated
    """
    tasks = []
    for _ in range(100):  # Increase concurrent coroutines
        tasks.append(_async_worker(duration))
    results = await asyncio.gather(*tasks)
    return sum(results)


def benchmark_tid_async(duration=10.0):
    """
    Benchmark amicrotime() async timestamp generation for specified duration.

    :param duration: How long to run the benchmark in seconds
    :return: Number of timestamps generated per second
    """
    start = time.time()
    count = asyncio.run(_async_benchmark(duration))
    elapsed = time.time() - start
    rate = int(count / elapsed)
    print(f"Total rate: {rate:,} timestamps/second")
    return rate


async def _async_thread_worker(duration, count_queue):
    """
    Async worker function for threads within processes.

    :param duration: How long to run in seconds
    :param count_queue: Queue to report count back
    """
    count = 0
    end = time.time() + duration
    while time.time() < end:
        await atimestamp()
        count += 1
    count_queue.put(count)


def _threaded_async_worker(duration, count_queue, num_async):
    """
    Thread worker that runs multiple async coroutines.

    :param duration: How long to run in seconds
    :param count_queue: Queue to report count
    :param num_async: Number of async coroutines per thread
    """

    async def run_workers():
        tasks = [_async_thread_worker(duration, count_queue) for _ in range(num_async)]
        await asyncio.gather(*tasks)

    asyncio.run(run_workers())


def _process_worker_async_threads(duration, result_queue, num_threads, num_async):
    """
    Process worker that spawns threads running async coroutines.

    :param duration: How long to run in seconds
    :param result_queue: Queue to report total count back to main process
    :param num_threads: Number of threads per process
    :param num_async: Number of async coroutines per thread
    """
    thread_queue = Queue()

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(_threaded_async_worker, duration, thread_queue, num_async)
            for _ in range(num_threads)
        ]

    process_total = sum(thread_queue.get() for _ in range(num_threads * num_async))
    result_queue.put(process_total)


def benchmark_tid_async_multi_tm(duration=10.0, num_processes=None, num_threads=None, num_async=10):
    """
    Benchmark amicrotime() using async coroutines within threads within processes.

    :param duration: How long to run the benchmark in seconds
    :param num_processes: Number of processes to use (defaults to CPU count)
    :param num_threads: Number of threads per process (defaults to 2)
    :param num_async: Number of async coroutines per thread (defaults to 10)
    :return: Total number of timestamps generated per second
    """
    if num_processes is None:
        num_processes = mp.cpu_count()
    if num_threads is None:
        num_threads = 2

    result_queue = mp.Queue()
    start = time.time()

    processes = []
    for _ in range(num_processes):
        p = mp.Process(
            target=_process_worker_async_threads,
            args=(duration, result_queue, num_threads, num_async),
        )
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    total_count = sum(result_queue.get() for _ in range(num_processes))
    elapsed = time.time() - start
    rate = int(total_count / elapsed)
    print(f"Total rate: {rate:,} timestamps/second")
    return rate


if __name__ == "__main__":
    print(f"Benchmarking timestamp at resolution {RESOLUTION}")
    print("\nSingle-threaded benchmark:")
    benchmark_tid()
    print("\nSingle-threaded async benchmark:")
    benchmark_tid_async()
    print("\nMulti-threaded benchmark:")
    benchmark_tid_multithreaded()
    print("\nMulti-process benchmark:")
    benchmark_tid_multiprocessing()
    print("\nMulti-process with threads benchmark:")
    benchmark_tid_multi_tm()
    print("\nAsync multi-process with threads benchmark:")
    benchmark_tid_async_multi_tm()
