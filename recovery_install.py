"""Prepare recovery-v1 from an approved release and explicit operator limits.

This module does not fetch configuration, sign transactions or write secrets.
Setup files and verifier bytecode stay bound to the existing release signature.
"""
import hashlib
import json
from pathlib import Path
import re


def ftu_wei(value):
    value=str(value).strip()
    if not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?',value):
        raise ValueError('Enter a non-negative FTU amount with at most 18 decimal places')
    whole,_,fraction=value.partition('.')
    amount=int(whole)*10**18+int((fraction+'0'*18)[:18])
    if amount>=2**256:raise ValueError('FTU amount exceeds the transaction range')
    return amount


def operator_limits(previous,gas_price,ask=input):
    from core.g_dkg_acceptance import AcceptanceLimits
    if previous:
        if type(previous.get('max_gas_price_wei')) is not int or previous['max_gas_price_wei']<=0:
            raise ValueError('Review the existing recovery gas-price ceiling')
        AcceptanceLimits.from_config(previous.get('acceptance',{}))
        return previous
    ceiling=int(ask(f'Maximum transaction gas price (wei per gas) [{gas_price*2}]: ').strip() or gas_price*2)
    if ceiling<=0:raise ValueError('Set a positive transaction gas-price ceiling')
    consent=ask('Enable automatic DKG acceptance within your collateral and fee limits? [y/N]: ').strip().lower()
    if consent not in ('','n','no','y','yes'):raise ValueError('Answer yes or no; no acceptance enabled')
    limits={'enabled':consent in ('y','yes')}
    if limits['enabled']:
        for name,label in (
            ('max_bond_wei','Maximum collateral per attempt from your stake (FTU)'),
            ('min_acceptance_fee_wei','Minimum acceptance fee (FTU)'),
            ('min_material_fee_wei','Minimum dealer material fee (FTU)'),
            ('min_share_key_fee_wei','Minimum share confirmation fee (FTU)')):
            limits[name]=ftu_wei(ask(label+': '))
        limits['max_concurrent_attempts']=int(ask('Maximum concurrent accepted attempts [1]: ').strip() or '1')
        limits['max_work_duration_seconds']=int(ask('Maximum combined material/share work window (seconds) [3600]: ').strip() or '3600')
        limits['max_dispute_duration_seconds']=int(ask('Maximum additional dispute-response window (seconds) [3600]: ').strip() or '3600')
    AcceptanceLimits.from_config(limits)
    return {'max_gas_price_wei':ceiling,'acceptance':limits}


def profile_document(state,config,manifest,bundles,chain_id,*,artifacts=None,zokrates=None):
    from artifact_store import destination
    from core.g_dkg_recovery_contracts import sha256_file
    state=Path(state).resolve()
    artifacts=Path(artifacts).resolve() if artifacts is not None else state/'artifacts'
    def local_path(path):
        path=path.resolve()
        return path.relative_to(state).as_posix() if path.is_relative_to(state) else str(path)
    binding=manifest['networks'].get(str(chain_id))
    if not binding or binding.get('dkg_attempt_protocol',0)!=1 or config.get('dkg_attempt_protocol')!=1:
        raise ValueError('Recovery-v1 requires a matching signed release network')
    if binding.get('contracts',{}).get('zkdkg_coordinator_v2_address','').lower()!=config['zkdkg_coordinator_v2_address'].lower():
        raise ValueError('Recovery coordinator differs from the signed release')
    profiles=[]
    for bundle in bundles:
        if 'n' not in bundle:continue
        pin=binding['verifiers'][bundle['id']]
        directory=destination(artifacts,bundle)
        hashes={name:row['sha256'] for name,row in bundle['files'].items()}
        if any(sha256_file(directory/name)!=digest for name,digest in hashes.items()):
            raise ValueError('Recovery setup files differ from the signed release')
        profiles.append({'n':bundle['n'],'t':bundle['t'],'verifier':pin['address'],
            'code_sha256':pin['code_sha256'],'directory':local_path(directory),'sha256':hashes})
    if not profiles:raise ValueError('Install at least one approved DKG proof profile')
    runtime=next(b for b in bundles if b['id']=='runtime-linux-x86_64')
    binary=Path(zokrates).resolve() if zokrates is not None else artifacts/'runtime-linux-x86_64/zokrates'
    digest=runtime['files']['zokrates']['sha256']
    if sha256_file(binary)!=digest:raise ValueError('ZoKrates differs from the signed release')
    document={'format':1,'chain_id':chain_id,'coordinator':config['zkdkg_coordinator_v2_address'],
        'profiles':profiles,'zokrates':{'path':local_path(binary),'sha256':digest}}
    raw=(json.dumps(document,sort_keys=True,indent=2)+'\n').encode()
    return raw,hashlib.sha256(raw).hexdigest()
