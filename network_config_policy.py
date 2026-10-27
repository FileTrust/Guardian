"""Keep the existing signed verifier bindings mandatory during config updates."""
import sys
from web3 import Web3

def validate(app,home,cfg,candidate,payload):
    sys.path.insert(0,str(app))
    from artifact_store import verify_manifest
    from network import check_network
    manifest=verify_manifest((home/'manifest.json').read_bytes(),(home/'manifest.sig').read_bytes(),app/'release-key.pub')
    bundles=[b for b in manifest['bundles'] if b['id'] in cfg['artifact_profiles']]
    if len(bundles)!=len(cfg['artifact_profiles']): raise ValueError('Installed profiles need a compatible signed artifact release')
    if any(key.startswith('protocol:') for key in candidate['changes']): raise ValueError('Protocol settings require a compatible Guardian application release')
    if any(key.startswith('ABI:') for key in candidate['changes']): raise ValueError('ABI changes require a compatible Guardian application release')
    proposed={**cfg,**candidate['fields']}
    check_network(Web3(Web3.HTTPProvider(proposed['rpc_url'],request_kwargs={'timeout':30})),proposed,manifest,bundles,lambda *_:None)
