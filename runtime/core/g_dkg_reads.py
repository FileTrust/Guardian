"""Bounded coherent view reads; never caches authorization or account state."""
from types import SimpleNamespace

from eth_utils.abi import get_abi_output_types
from web3 import Web3
from web3._utils.abi import map_abi_data
from web3._utils.normalizers import BASE_RETURN_NORMALIZERS

from .g_dkg_rpc import ReadRetryHTTPProvider, ReadBatchUnavailable


def read_contracts(w3, functions, *, block_identifier='latest', expected_chain_id=None):
    functions = list(functions)
    if not functions:
        return []
    if len(functions) > 64:
        raise ValueError('Too many DKG view reads')
    provider = getattr(w3, 'provider', None)
    if not isinstance(provider, ReadRetryHTTPProvider) or expected_chain_id is None:
        return [fn.call(block_identifier=block_identifier) for fn in functions]
    if int(w3.eth.chain_id) != expected_chain_id:
        raise RuntimeError('DKG view batch belongs to another chain')
    if any(fn.abi.get('stateMutability') not in ('view', 'pure') for fn in functions):
        raise ValueError('DKG batch functions must be read-only')
    block = w3.eth.get_block(block_identifier)
    number, digest = int(block['number']), Web3.to_hex(block['hash'])
    account = getattr(w3.eth, 'default_account', None)
    sender = {'from': account} if isinstance(account, str) and Web3.is_address(account) else {}
    results = []
    for start in range(0, len(functions), 16):
        page = functions[start:start+16]
        if getattr(provider, '_dkg_batch_supported', True) is False:
            results.extend(fn.call(block_identifier=number) for fn in page)
            continue
        try:
            values = provider.verified_read_batch([
                ('eth_call', [{**sender, 'to': fn.address, 'data': fn._encode_transaction_data()}, hex(number)])
                for fn in page])
        except ReadBatchUnavailable:
            provider._dkg_batch_supported = False
            results.extend(fn.call(block_identifier=number) for fn in page)
            continue
        for fn, value in zip(page, values):
            try:
                types = get_abi_output_types(fn.abi)
                decoded = w3.codec.decode(types, Web3.to_bytes(hexstr=value))
                decoded = map_abi_data(BASE_RETURN_NORMALIZERS, types, decoded)
            except Exception:
                raise RuntimeError('DKG view response differs from its approved ABI') from None
            results.append(decoded[0] if len(decoded) == 1 else decoded)
    if Web3.to_hex(w3.eth.get_block(number)['hash']) != digest:
        raise RuntimeError('DKG view snapshot changed; retrying without accepting it')
    return results


def read_records(w3, functions, **kwargs):
    functions = list(functions)
    records = []
    for fn, value in zip(functions, read_contracts(w3, functions, **kwargs)):
        fields = fn.abi['outputs']
        if len(fields) == 1 and fields[0]['type'] == 'tuple':
            fields = fields[0]['components']
        records.append(SimpleNamespace(**{f['name']: item for f, item in zip(fields, value)}))
    return records
