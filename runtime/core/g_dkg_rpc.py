"""Optional read pacing for a development fleet sharing a bounded RPC gateway."""
import math
import threading
import time

from web3.middleware import Web3Middleware
from web3 import HTTPProvider


class ReadRetryHTTPProvider(HTTPProvider):
    """Retry transient HTTP failures for reads, including gas estimation.

    Broadcasts retain the transaction coordinator's identical-byte handling.
    RPC contract errors and valid null results pass through unchanged.
    """
    def make_request(self, method, params):
        if str(method) in ('eth_sendRawTransaction', 'eth_sendTransaction'):
            return super().make_request(method, params)
        from requests.exceptions import ConnectionError, HTTPError, Timeout
        from .g_lifecycle import STOP
        for attempt in range(8):
            try:
                return super().make_request(method, params)
            except (ConnectionError, HTTPError, Timeout) as error:
                if isinstance(error, HTTPError) and (error.response is None or
                        error.response.status_code != 429 and error.response.status_code < 500):
                    raise
                if attempt == 7 or STOP.wait(min(8, 0.5 * 2**attempt)):
                    raise


def install_read_pacing(w3, interval, stop, *, clock=time.monotonic):
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not math.isfinite(interval) or not 0 <= interval <= 5:
        raise ValueError('Invalid DKG RPC read interval')
    if not interval:
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
