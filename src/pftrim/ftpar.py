"""Ordered multi-process helper for per-bundle ftrace work (stdlib only).

The heavy per-event decoding of ftrace bundles is a pure function of
the bundle bytes; everything order-dependent stays in the main process.
`OrderedPool` batches tasks, runs them in worker processes and hands the
results back strictly in submission order, with a bounded number of
batches in flight (memory stays O(jobs * batch)).

With jobs <= 1 (or small inputs) tasks run in-process through the very
same batch function, so both paths share one implementation.
"""

from __future__ import annotations

import collections
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor

from .env import getenv

BATCH_BYTES = 2 << 20
BATCH_TASKS = 64
_MIN_BYTES_DEFAULT = 64 << 20

_default_jobs: int | None = None


def set_default_jobs(jobs: int | None) -> None:
    """CLI -j/--jobs: process-wide default for scan/engine."""
    global _default_jobs
    _default_jobs = jobs


def resolve_jobs(jobs: int | None = None) -> int:
    if jobs is None:
        jobs = _default_jobs
    if jobs is None:
        env = getenv("JOBS")
        if env:
            jobs = int(env)
    if jobs is None:
        # the ordered main process is the bottleneck beyond ~3 workers
        # (big trace: jobs 3 == 4 in speed, ~70 MB less RSS)
        jobs = min((os.cpu_count() or 2) - 1, 3)
    return max(1, int(jobs))


def min_parallel_bytes() -> int:
    env = getenv("PAR_MIN_BYTES")
    return int(env) if env else _MIN_BYTES_DEFAULT


def use_pool(jobs: int, input_bytes: int) -> bool:
    return jobs > 1 and input_bytes >= min_parallel_bytes()


class OrderedPool:
    """add(task, nbytes, meta) -> yields (meta, result) pairs that are
    ready in submission order; finish() yields the rest.

    ``batch_fn(list_of_tasks) -> list_of_results`` must be a picklable
    module-level function. ``initializer/initargs`` run once per worker.
    """

    def __init__(self, batch_fn, jobs: int, *, initializer=None,
                 initargs=(), max_inflight: int | None = None):
        self.batch_fn = batch_fn
        self.jobs = jobs
        self._tasks: list = []
        self._metas: list = []
        self._bytes = 0
        self._fifo: collections.deque = collections.deque()
        # finished-but-unconsumed results are unpickled into the main
        # process: keep the queue short (main is the serial bottleneck)
        self._max_inflight = max_inflight or jobs + 2
        self._ex = None
        if jobs > 1:
            self._ex = ProcessPoolExecutor(
                max_workers=jobs,
                mp_context=multiprocessing.get_context("spawn"),
                initializer=initializer, initargs=initargs)
        elif initializer is not None:
            initializer(*initargs)

    def add(self, task, nbytes: int, meta=None):
        self._tasks.append(task)
        self._metas.append(meta)
        self._bytes += nbytes
        if self._ex is None:
            return self._flush_inline()
        if self._bytes >= BATCH_BYTES or len(self._tasks) >= BATCH_TASKS:
            self._submit()
        return self._ready(self._max_inflight)

    def finish(self):
        if self._ex is None:
            return self._flush_inline()
        if self._tasks:
            self._submit()
        return self._ready(1)

    def _flush_inline(self):
        tasks, metas = self._tasks, self._metas
        self._tasks, self._metas, self._bytes = [], [], 0
        if not tasks:
            return ()
        return zip(metas, self.batch_fn(tasks))

    def _submit(self):
        fut = self._ex.submit(self.batch_fn, self._tasks)
        self._fifo.append((fut, self._metas))
        self._tasks, self._metas, self._bytes = [], [], 0

    def _ready(self, limit: int):
        """Drain the FIFO head while len(fifo) >= limit (blocking)."""
        out = []
        fifo = self._fifo
        while fifo and len(fifo) >= limit:
            fut, metas = fifo.popleft()
            out.extend(zip(metas, fut.result()))
        return out

    def close(self) -> None:
        if self._ex is not None:
            self._ex.shutdown(wait=True, cancel_futures=True)
            self._ex = None
        self._fifo.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
