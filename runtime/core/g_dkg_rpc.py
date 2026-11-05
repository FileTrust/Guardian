"""Optional read pacing for a development fleet sharing a bounded RPC gateway."""
import math
import threading
import time

from web3.middleware import Web3Middleware
from web3 import HTTPProvider


class ReadBudget:
    """Per-provider bound shared by worker threads, with slow recovery.

    The configured floor is never crossed. Transport failures increase spacing;
    only 32 consecutive successful reads permit one small reduction. Contract
    results are never cached or changed, and broadcasts do not use this budget.
    """
    def __init__(self, interval, minimum, stop, clock=time.monotonic):
        self.interval, self.minimum = interval, minimum
        self.maximum = max(interval, 2.0)
        self.stop, self.clock = stop, clock
        self.lock = threading.Lock()
        self.next_read = 0
        self.successes = 0

    def before(self):
        from requests.exceptions import ConnectionError
        with self.lock:
            delay = max(0, self.next_read-self.clock())
            if delay and self.stop.wait(delay):
                raise ConnectionError('Guardian read cancelled for shutdown')
            self.next_read = self.clock()+self.interval

    def success(self):
        with self.lock:
            self.successes += 1
            if self.successes >= 32:
                self.interval = max(self.minimum, self.interval*0.8)
                self.successes = 0

    def failure(self):
        with self.lock:
            self.interval = min(self.maximum, max(self.minimum, self.interval*2))
            self.successes = 0
            self.next_read = max(self.next_read, self.clock()+self.interval)


class ReadRetryHTTPProvider(HTTPProvider):
    """Retry transient HTTP failures for reads, including gas estimation.

    Broadcasts retain the transaction coordinator's identical-byte handling.
    RPC contract errors and valid null results pass through unchanged.
    """
    def set_read_retry_attempts(self, attempts):
        if type(attempts) is not int or not 1 <= attempts <= 8:
            raise ValueError('DKG read retries must be between one and eight')
        self._read_retry_attempts = attempts

    def make_request(self, method, params):
        if str(method) in ('eth_sendRawTransaction', 'eth_sendTransaction'):
            return super().make_request(method, params)
        from requests.exceptions import ConnectionError, HTTPError, Timeout
        from .g_lifecycle import STOP
        attempts = getattr(self, '_read_retry_attempts', 8)
        budget = getattr(self, '_read_budget', None)
        for attempt in range(attempts):
            try:
                if budget is not None:
                    budget.before()
                result = super().make_request(method, params)
                if budget is not None:
                    budget.success()
                return result
            except (ConnectionError, HTTPError, Timeout) as error:
                if isinstance(error, HTTPError) and (error.response is None or
                        error.response.status_code != 429 and error.response.status_code < 500):
                    raise
                if budget is not None:
                    budget.failure()
                if attempt == attempts - 1 or STOP.wait(min(8, 0.5 * 2**attempt)):
                    raise


def install_read_pacing(w3, interval, stop, *, clock=time.monotonic, minimum_interval=None):
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not math.isfinite(interval) or not 0 <= interval <= 5:
        raise ValueError('Invalid DKG RPC read interval')
    if minimum_interval is not None and (isinstance(minimum_interval, bool) or
            not isinstance(minimum_interval, (int, float)) or not math.isfinite(minimum_interval)
            or not 0 < minimum_interval <= interval):
        raise ValueError('Invalid minimum DKG RPC read interval')
    if not interval:
        return
    if minimum_interval is not None:
        if not isinstance(getattr(w3, 'provider', None), ReadRetryHTTPProvider):
            raise ValueError('Adaptive pacing requires the bounded read provider')
        w3.provider._read_budget = ReadBudget(interval, minimum_interval, stop, clock)
        return

    class PacedReads(Web3Middleware):
        def __init__(self, provider):
            super().__init__(provider)
            self.next_read = 0
            self.lock = threading.Lock()

        def request_processor(self, method, params):
            if str(method) not in ('eth_sendRawTransaction', 'eth_sendTransaction'):
                with self.lock:
                    delay = max(0, self.next_read - clock())
                    if delay:
                        stop.wait(delay)
                    self.next_read = clock() + interval
            return method, params

    w3.middleware_onion.add(PacedReads, name='dkg-read-pacing')
