"""Recovery custody paths and strict reads, separate from legacy deployments.

No RPC or configuration is loaded here. A configuration must explicitly pin
its chain and coordinator; changing deployments never searches old share files.
"""
from pathlib import Path

from web3 import Web3

from .g_crypto import BABY_L,baby_mul
from .g_dkg_cipher import material_id_bytes
from .g_dkg_identity import read_private_json


def deployment_directory(cfg):
    chain_id=cfg.DKG_RECOVERY.get('chain_id')
    if type(chain_id) is not int or chain_id<=0:
        raise ValueError('Recovery custody needs its explicitly approved chain ID')
    coordinator=Web3.to_checksum_address(cfg.ZKDKG_COORDINATOR_V2_ADDRESS).lower()
    if int(coordinator,16)==0:
        raise ValueError('Recovery custody needs its approved coordinator')
    return Path(cfg.ROOT)/'dkg-recovery-v1'/str(chain_id)/coordinator


def active_share_path(cfg,file_id,epoch,version,n,t,index):
    file_id=material_id_bytes(file_id).hex()
    values=(epoch,version,n,t,index)
    if any(type(v) is not int for v in values) or not (epoch>0 and version>0 and 1<=index<=n and 2<=t<=n<=20):
        raise ValueError('Invalid recovery custody share scope')
    return deployment_directory(cfg)/'shares'/f'v2_dkg_file_{file_id}_n{n}_t{t}_k{epoch}_v{version}_final_share_{index}.json'


def active_share_files(cfg):
    return sorted((deployment_directory(cfg)/'shares').glob('v2_dkg_file_*_final_share_*.json'))


def load_active_share(cfg,file_id,epoch,version,n,t,index):
    path=active_share_path(cfg,file_id,epoch,version,n,t,index)
    data=read_private_json(path)
    try:
        if (data['kind']!='zkdkg_v2_final_share' or
            material_id_bytes(data['fileId'])!=material_id_bytes(file_id) or
            (data['keyEpoch'],data['shareVersion'],data['n'],data['t'],data['index'])!=(epoch,version,n,t,index)):
            raise ValueError()
        material_id_bytes(data['materialId'])
        share=int(data['share'])
        if not 0<share<BABY_L or baby_mul(share)!=(int(data['vkx']),int(data['vky'])):
            raise ValueError()
    except (KeyError,TypeError,ValueError):
        raise RuntimeError('Recovery custody metadata does not match the requested active share') from None
    return index,share
