"""Explicit recovery-escrow withdrawal; private keys never enter arguments."""
import argparse
from pathlib import Path
import sys

if __name__=='__main__':
    code_root=Path(__file__).resolve().parents[1]
    if (code_root/'ft_update_bootstrap.py').is_file():
        sys.path.insert(0,str(code_root))
        from ft_update_bootstrap import enter
        enter(code_root)

from web3 import Web3
from web3.logs import DISCARD

from .g_dkg_attempt_tx import DurableSender
from .g_dkg_recovery_contracts import RecoveryContracts


def _native(value):
    whole,fraction=divmod(int(value),10**18)
    return str(whole) if not fraction else f'{whole}.{fraction:018d}'.rstrip('0')


def claim(cfg,w3,account,approve):
    if cfg.DKG_ATTEMPT_PROTOCOL!=1 or cfg.DKG_RECOVERY.get('chain_id')!=w3.eth.chain_id:
        raise ValueError('Select the approved recovery deployment before withdrawing its credits')
    c=RecoveryContracts(w3,cfg.ZKDKG_COORDINATOR_V2_ADDRESS,cfg.ACL_ADDRESS,
        cfg.GUARDIAN_REGISTRY_ADDRESS,cfg.STAKING_MANAGER_ADDRESS)
    sender=DurableSender(w3,account,nonce_root=cfg.ROOT,max_gas=300000,
        max_gas_price_wei=int(cfg.DKG_RECOVERY['max_gas_price_wei']))
    recovered=sender.recover()
    def paid(receipt):
        events=c.escrow.events.Claimed().process_receipt(receipt,errors=DISCARD)
        amounts=[event['args']['amount'] for event in events if event['address'].lower()==c.escrow.address.lower()
            and event['args']['account'].lower()==account.address.lower() and event['args']['recipient'].lower()==account.address.lower()]
        if len(amounts)==1:
            print(f'DKG credits received by your wallet: {_native(amounts[0])} FTU',flush=True)
            return int(amounts[0])
        return None
    previous=paid(recovered) if recovered else None
    amount=int(c.escrow.functions.claimable(account.address).call())
    if not amount:
        if previous is None:print('No DKG escrow credits are available for this wallet',flush=True)
        return previous or 0
    fn=c.escrow.functions.withdrawTo(account.address)
    gas,price=sender.gas_quote(fn)
    print(f'Wallet: {account.address}\nClaimable DKG credits: {_native(amount)} FTU\nMaximum withdrawal transaction fee: {_native(gas*price)} FTU',flush=True)
    if approve({'amount_wei':amount,'maximum_fee_wei':gas*price,'beneficiary':account.address}) is not True:
        print('Withdrawal cancelled; credits remain in escrow',flush=True)
        return 0
    # Freeze the reviewed fee ceiling, even if the node's general ceiling is higher.
    approved=DurableSender(w3,account,nonce_root=cfg.ROOT,max_gas=gas,max_gas_price_wei=price)
    receipt=approved(fn,f'escrow-claim:{c.escrow.address.lower()}:{w3.eth.get_transaction_count(account.address,"pending")}')
    amount=paid(receipt)
    if amount is None:raise RuntimeError('The receipt does not confirm a withdrawal to this wallet')
    return amount


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm',action='store_true',help='Approve a withdrawal within configured fee limits')
    args=parser.parse_args()
    from . import g_config as cfg
    w3=Web3(Web3.HTTPProvider(cfg.RPC_URL,request_kwargs={'timeout':30}))
    account=w3.eth.account.from_key(cfg.SH_PRIVATE_KEY)
    claim(cfg,w3,account,lambda _:args.confirm or input('Withdraw these credits to your wallet? [y/N]: ').strip().lower() in ('y','yes'))


if __name__=='__main__':main()
