"""
Async runner - runs all collectors in parallel using asyncio + ThreadPoolExecutor.
The collectors themselves use requests (sync), so we wrap them in threads.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Callable, Tuple


async def _run_in_thread(executor, fn: Callable, label: str) -> Tuple[str, list]:
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(executor, fn)
        return label, result or []
    except Exception as e:
        print(f"  [!] {label} failed: {e}")
        return label, []


async def collect_all_async(collectors: List[Tuple[str, Callable]], max_workers: int = 6) -> dict:
    """
    Run all collectors in parallel.
    collectors: list of (label, callable) pairs where callable() returns list
    Returns dict: {label: [data points]}
    """
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks = [_run_in_thread(executor, fn, label) for label, fn in collectors]
        results = await asyncio.gather(*tasks)

    return dict(results)


def run_collectors_parallel(collectors: List[Tuple[str, Callable]], max_workers: int = 6) -> dict:
    """Synchronous entry point for running collectors in parallel."""
    return asyncio.run(collect_all_async(collectors, max_workers=max_workers))
