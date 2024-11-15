import threading
import multiprocessing as mp
from queue import Queue
from iscc_crypto.microtime import microtime
from loguru import logger as log
import time


def _thread_worker(duration: float, results: Queue):
    """Thread worker that validates monotonicity and reports count."""
    start = time.time()
    last = 0
    count = 0

    while (time.time() - start) < duration:
        ts = microtime()
        assert ts > last, f"Timestamp {ts} not greater than {last}"
        last = ts
        count += 1

        # Report progress periodically
        if count % 1000 == 0:
            results.put(("progress", count))

    # Report final count
    results.put(("final", count))


def _process_worker(duration: float, results: mp.Queue):
    """Process worker that runs multiple threads and aggregates counts."""
    thread_results = Queue()
    threads = []
    num_threads = 8
    process_count = 0

    # Start threads
    for _ in range(num_threads):
        t = threading.Thread(target=_thread_worker, args=(duration, thread_results))
        t.start()
        threads.append(t)

    # Wait for threads to finish
    for t in threads:
        t.join()

    # Collect all results after threads finish
    while not thread_results.empty():
        status, count = thread_results.get()
        if status == "final":
            process_count += count

    # Report final count for this process
    results.put(process_count)


def test_microtime_multi():
    """Test microtime across multiple processes and threads."""
    duration = 5.0  # Test duration in seconds
    num_processes = 8

    # Create process pool and result queue
    results = mp.Queue()
    processes = []

    # Start processes
    for _ in range(num_processes):
        p = mp.Process(target=_process_worker, args=(duration, results))
        p.start()
        processes.append(p)

    # Wait for processes
    for p in processes:
        p.join()

    # Collect final counts from all processes
    total_count = 0
    while not results.empty():
        process_count = results.get()
        total_count += process_count

    rate = total_count / duration
    log.debug(
        f"\nGenerated {total_count:,} unique timestamps "
        f"across {num_processes} processes x 8 threads "
        f"in {duration:.1f} seconds "
        f"({rate:,.0f} t/s)"
    )

    assert total_count > 0, "No timestamps were generated"
