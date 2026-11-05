"""Optional read pacing for a development fleet sharing a bounded RPC gateway."""
import math
import json
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

    def before(self, units=1):
        from requests.exceptions import ConnectionError
        with self.lock:
            delay = max(0, self.next_read-self.clock())
            if delay and self.stop.wait(delay):
                raise ConnectionError('Guardian read cancelled for shutdown')
            self.next_read = self.clock()+self.interval*units

    def success(self, units=1):
        with self.lock:
            self.successes += units
            if self.successes >= 32:
                self.interval = max(self.minimum, self.interval*0.8)
                self.successes %= 32

    def failure(self):
        with self.lock:
            self.interval = min(self.maximum, max(self.minimum, self.interval*2))
            self.successes = 0
            self.next_read = max(self.next_read, self.clock()+self.interval)


class ReadBatchUnavailable(RuntimeError):
    """The endpoint explicitly does not implement JSON-RPC batches."""


class ReadRetryHTTPProvider(HTTPProvider):
    """Retry transient HTTP failures for reads, including gas estimation.

    Broadcasts retain the transaction coordinator's identical-byte handling.
    RPC contract errors and valid null results pass through unchanged.
    """
    def __init__(self, *args, **kwargs):
        # One retry layer only; do not multiply our limit by Web3's retries.
        kwargs['exception_retry_configuration'] = None
        kwargs['request_kwargs'] = {'timeout': (5, 15), **(kwargs.get('request_kwargs') or {})}
        super().__init__(*args, **kwargs)

    def set_read_retry_attempts(self, attempts):
        if type(attempts) is not int or not 1 <= attempts <= 8:
            raise ValueError('DKG read retries must be between one and eight')
        self._read_retry_attempts = attempts

    def make_request(self, method, params):
        if str(method) in ('eth_sendRawTransaction', 'eth_sendTransaction'):
            return super().make_request(method, params)
        parent = super().make_request
        return self._retry_read(lambda: parent(method, params))

    def _retry_read(self, operation, units=1):
        from requests.exceptions import ConnectionError, HTTPError, Timeout
        from .g_lifecycle import STOP
        attempts = getattr(self, '_read_retry_attempts', 8)
        budget = getattr(self, '_read_budget', None)
        for attempt in range(attempts):
            try:
                if budget is not None:
                    budget.before(units)
                result = operation()
                if budget is not None:
                    budget.success(units)
                return result
            except (ConnectionError, HTTPError, Timeout) as error:
                if isinstance(error, HTTPError) and (error.response is None or
                        error.response.status_code != 429 and error.response.status_code < 500):
                    raise
                if budget is not None:
                    budget.failure()
                if attempt == attempts - 1 or STOP.wait(min(8, 0.5 * 2**attempt)):
                    raise

    def verified_read_batch(self, requests):
        """Read-only batch with exact ID matching using this TLS/session setup."""
        if not requests or len(requests) > 16 or any(method != 'eth_call' for method, _ in requests):
            raise ValueError('DKG batches permit at most sixteen contract reads')
        encoded = self.encode_batch_rpc_request(requests)
        identifiers = [r['id'] for r in json.loads(encoded)]

        def request():
            raw = self._request_session_manager.make_post_request(
                self.endpoint_uri, encoded, **self.get_request_kwargs())
            response = self.decode_rpc_response(raw)
            if (isinstance(response, dict) and 'result' not in response and
                    isinstance(response.get('error'), dict) and
                    response['error'].get('code') in (-32600, -32601)):
                raise ReadBatchUnavailable('RPC endpoint does not support read batches')
            if not isinstance(response, list) or len(response) != len(identifiers):
                raise RuntimeError('DKG batch response is incomplete')
            by_id = {}
            for item in response:
                if (not isinstance(item, dict) or type(item.get('id')) is not int or
                        item.get('jsonrpc') != '2.0' or
                        item['id'] in by_id or item['id'] not in identifiers or
                        'error' in item or not isinstance(item.get('result'), str)):
                    raise RuntimeError('DKG batch response is invalid')
                by_id[item['id']] = item['result']
            return [by_id[i] for i in identifiers]
        return self._retry_read(request, len(requests))


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
        budget = ReadBudget(interval, minimum_interval, stop, clock)
        if isinstance(getattr(w3, 'provider', None), ReadRetryHTTPProvider):
            w3.provider._read_budget = budget
            return
        # The DKG entry point also supports Web3's ordinary HTTPProvider.
        # Wrap its existing transport rather than replacing TLS/session/auth
        # settings. Errors propagate unchanged, never become empty evidence.
        class AdaptiveReads(Web3Middleware):
            def wrap_make_request(self, make_request):
                def request(method, params):
                    if str(method) in ('eth_sendRawTransaction', 'eth_sendTransaction'):
                        return make_request(method, params)
                    from requests.exceptions import ConnectionError, HTTPError, Timeout
                    budget.before()
                    try:
                        result = make_request(method, params)
                    except (ConnectionError, HTTPError, Timeout) as error:
                        if not isinstance(error, HTTPError) or (error.response is not None and
                                (error.response.status_code == 429 or error.response.status_code >= 500)):
                            budget.failure()
                        raise
                    budget.success()
                    return result
                return request
        w3.middleware_onion.add(AdaptiveReads, name='dkg-adaptive-read-pacing')
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
