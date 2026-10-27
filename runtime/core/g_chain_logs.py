"""Reading chain logs in ranges a real chain will actually serve.

Chains cap log queries. Cosmos refuses anything wider than 10,000 blocks:

    maximum [from, to] blocks distance: 10000

A one-second chain passes that in under three hours, so "give me everything from
block zero" is not a slow query — it is a query that always fails on a chain
older than an afternoon. On 2026-08-31 that exact limit emptied discovery's
keeper table mid-run and stopped every upload.

Deliberately free of configuration and of any chain connection, so it can be
imported and tested on its own.
"""
from __future__ import annotations

LOG_WINDOW_BLOCKS = 9_000


def logs_backward(event, argument_filters=None, window: int = LOG_WINDOW_BLOCKS,
                  lookback: int = 8):
    """Search newest-first and stop at the first window that matches.

    For "does this exist?" questions, where the answer is usually recent and
    walking the whole chain to say "no" is not acceptable. Bounded by lookback.
    """
    try:
        head = int(event.w3.eth.block_number)
    except Exception:
        return []

    to_block = head
    for _ in range(max(1, lookback)):
        from_block = max(0, to_block - window)
        found = event.get_logs(
            from_block=from_block,
            to_block=to_block,
            argument_filters=argument_filters or {},
        )
        if found:
            return found
        if from_block == 0:
            break
        to_block = from_block - 1
    return []


def logs_forward(event, from_block: int, to_block: int, argument_filters=None,
                 window: int = LOG_WINDOW_BLOCKS):
    """Collect every matching log between two blocks, paged into servable ranges.

    For questions that genuinely need a whole range. Callers that run on a loop
    should remember the last block they reached and pass it as from_block, so
    each pass reads only what is new.
    """
    out = []
    start = max(0, int(from_block))
    end = int(to_block)
    while start <= end:
        stop = min(end, start + window - 1)
        out.extend(
            event.get_logs(
                from_block=start,
                to_block=stop,
                argument_filters=argument_filters or {},
            )
        )
        start = stop + 1
    return out
