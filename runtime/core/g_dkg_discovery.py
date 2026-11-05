"""Restart-safe discovery hints from the bound registry's canonical events.

Events authorize no work: the normal worker rechecks assignment, funding,
consent and immutable context. Accepted duties remain in its separate catalog.
"""
from pathlib import Path

from web3 import Web3
from requests.exceptions import ConnectionError

from .g_dkg_identity import private_lock, read_private_json
from .g_secret_files import write_json_atomic


class OfferDiscovery:
    def __init__(self, w3, contracts, root):
        self.w3, self.c = w3, contracts
        self.root = Path(root) / 'catalog' / 'discovery'

    def _initial_block(self, latest):
        # This approved registry has no proxy or self-destruct lifecycle.
        # An archive-unavailable RPC falls back to complete log backfill.
        try:
            low, high = 0, latest
            while low < high:
                middle = (low + high) // 2
                if self.w3.eth.get_code(self.c.registry.address, block_identifier=middle):
                    high = middle
                else:
                    low = middle + 1
            if low and self.w3.eth.get_code(self.c.registry.address, block_identifier=low - 1):
                return 0
            return low
        except Exception:
            return 0

    def _load(self, latest):
        path = self.root / 'cursor.json'
        chain = int(self.w3.eth.chain_id)
        first = Web3.to_hex(self.w3.eth.get_block(1)['hash'])
        if path.exists():
            state = read_private_json(path)
            if (state['chain_id'], state['registry'], state['first_block']) != (
                    chain, self.c.registry.address.lower(), first):
                raise RuntimeError('Discovery cursor belongs to another chain incarnation')
            if state['checkpoint'] is not None:
                number, digest = state['checkpoint']
                if number > latest or Web3.to_hex(self.w3.eth.get_block(number)['hash']) != digest:
                    # Replay all registry history; never guess a safe reorg depth.
                    state['next_block'] = self._initial_block(latest)
                    state['checkpoint'] = None
            return state
        return dict(chain_id=chain, registry=self.c.registry.address.lower(), first_block=first,
                    next_block=self._initial_block(latest), checkpoint=None, pending=[])

    def discover(self, *, page_blocks=2000, limit=16):
        if (type(page_blocks) is not int or type(limit) is not int or
                not 1 <= page_blocks <= 9000 or not 1 <= limit <= 64):
            raise ValueError('Invalid bounded discovery page')
        with private_lock(self.root):
            latest = int(self.w3.eth.block_number)
            state = self._load(latest)
            if len(state['pending']) < 128 and state['next_block'] <= latest:
                start = state['next_block']; stop = min(latest, start + page_blocks - 1)
                block = self.w3.eth.get_block(stop)
                rows = self.c.registry.events.AttemptOpened().get_logs(from_block=start, to_block=stop)
                if Web3.to_hex(self.w3.eth.get_block(stop)['hash']) != Web3.to_hex(block['hash']):
                    raise ConnectionError('Canonical discovery range changed; retrying without advancing')
                verified_blocks = {stop: Web3.to_hex(block['hash'])}
                for row in rows:
                    if row.get('address', self.c.registry.address).lower() != self.c.registry.address.lower():
                        raise RuntimeError('Discovery event came from a different registry')
                    number = int(row['blockNumber'])
                    if number not in verified_blocks:
                        verified_blocks[number] = Web3.to_hex(self.w3.eth.get_block(number)['hash'])
                    if row.get('removed') or Web3.to_hex(row['blockHash']) != verified_blocks[number]:
                        raise ConnectionError('Discovery event is not canonical; cursor retained')
                    identifier = Web3.to_hex(row['args']['attemptId'])
                    if identifier not in state['pending']:
                        state['pending'].append(identifier)
                # Persist hints and cursor together before handing off any job.
                state['next_block'] = stop + 1
                state['checkpoint'] = [stop, Web3.to_hex(block['hash'])]
            write_json_atomic(self.root / 'cursor.json', state)
            identifiers = state['pending'][:limit]
        found = []
        absent = []
        for identifier in identifiers:
            material = self.c.controller.functions.materialForRegistryId(identifier).call()
            if any(material):
                found.append((identifier, Web3.to_hex(material)))
            else:
                from .g_dkg_recovery_contracts import record
                if record(self.c.registry.functions.getAttempt(identifier)).state == 0:
                    # Discard only a no-longer-canonical discovery hint. The
                    # separate custody and signed-transaction ledgers remain.
                    absent.append(identifier)
        self.acknowledge(absent)
        return found

    def acknowledge(self, identifiers):
        if not identifiers:
            return
        with private_lock(self.root):
            path = self.root / 'cursor.json'
            state = read_private_json(path)
            state['pending'] = [i for i in state['pending'] if i not in identifiers]
            write_json_atomic(path, state)
