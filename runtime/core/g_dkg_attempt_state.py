"""Protected, attempt-scoped dealer material and staged receiver shares.

No blockchain calls. Callers must supply authoritative context and publication
status; RPC uncertainty must never be converted to published=False. Candidate
shares remain separate from active custody until the exact material ID activates.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from .g_crypto import (BABY_L, baby_mul, poly_eval, v2_dkg_generate_local,
                       v2_dkg_generate_refresh_local)
from .g_dkg_cipher import material_id_bytes
from .g_dkg_identity import private_lock, read_private_json
from .g_secret_files import write_json_atomic


@dataclass(frozen=True)
class MaterialContext:
    material_id: str
    context_hash: str
    file_id: str
    epoch: int
    version: int
    dealer_index: int
    n: int
    t: int

    def __post_init__(self):
        for name in ['material_id', 'context_hash', 'file_id']:
            object.__setattr__(self, name, '0x' + material_id_bytes(getattr(self, name)).hex())
        if any(type(v) is not int for v in [self.epoch, self.version, self.dealer_index, self.n, self.t]):
            raise ValueError('DKG indices and profile must be integers')
        if not (self.epoch > 0 and self.version > 0 and 1 <= self.dealer_index <= 20 and 2 <= self.t <= self.n <= 20):
            raise ValueError('Invalid accepted DKG material context')
        if self.version == 1 and self.dealer_index > self.n:
            raise ValueError('Fresh dealer index exceeds its committee')


@dataclass(frozen=True)
class DealerMaterial:
    coefficients: tuple[int, ...] = field(repr=False)
    commitments: tuple[tuple[int, int], ...]
    shares: tuple[int, ...] = field(repr=False)


def attempt_directory(root: Path, material_id) -> Path:
    return Path(root) / 'attempts' / material_id_bytes(material_id).hex()


def _validated_material(data, context, constant_share, refresh_weight):
    try:
        if data['format'] != 1 or data['context'] != asdict(context):
            raise ValueError()
        coefficients = tuple(int(v) for v in data['coefficients'])
        points = tuple(tuple(int(v) for v in p) for p in data['commitments'])
        shares = tuple(int(v) for v in data['shares'])
        if len(coefficients) != context.t or len(points) != context.t or len(shares) != context.n:
            raise ValueError()
        if any(not 0 <= v < BABY_L for v in (*coefficients, *shares)):
            raise ValueError()
        if tuple(baby_mul(v) or (0, 1) for v in coefficients) != points:
            raise ValueError()
        if tuple(poly_eval(coefficients, j, BABY_L) for j in range(1, context.n+1)) != shares:
            raise ValueError()
        if context.version > 1 and (coefficients[0] != constant_share or data.get('refreshWeight') != str(refresh_weight)):
            raise ValueError()
        return DealerMaterial(coefficients, points, shares)
    except (KeyError, TypeError, ValueError):
        raise RuntimeError('Saved DKG material does not match the accepted attempt; restore its backup') from None


def load_dealer_material(root: Path, context: MaterialContext, *, published: bool, old_share: int | None = None,
                         refresh_weight: int | None = None):
    if type(published) is not bool:
        raise ValueError('Publication status must be an authoritative boolean')
    if (context.version == 1) != (old_share is None):
        raise ValueError('A refresh needs its previous active share')
    if old_share is not None and (type(old_share) is not int or not 0 <= old_share < BABY_L):
        raise ValueError('Invalid previous active share')
    if old_share is None and refresh_weight is not None:
        raise ValueError('A fresh attempt has no refresh weight')
    if old_share is not None and (type(refresh_weight) is not int or not 0 < refresh_weight < BABY_L):
        raise ValueError('A refresh needs its frozen on-chain dealer weight')
    constant_share = None if old_share is None else old_share * refresh_weight % BABY_L
    directory = attempt_directory(root, context.material_id)
    with private_lock(directory):
        path = directory / f'dealer-{context.dealer_index}.json'
        if path.exists() or path.is_symlink():
            return _validated_material(read_private_json(path), context, constant_share, refresh_weight)
        if published:
            raise RuntimeError('Published DKG material is missing locally; refusing to generate a replacement')
        if old_share is None:
            coefficients, points, shares = v2_dkg_generate_local(context.t, context.n)
        else:
            coefficients, points, shares = v2_dkg_generate_refresh_local(constant_share, context.t, context.n)
        data = {'format': 1, 'context': asdict(context), 'coefficients': [str(v) for v in coefficients],
                'commitments': [list(p or (0, 1)) for p in points], 'shares': [str(v) for v in shares],
                'refreshWeight': None if refresh_weight is None else str(refresh_weight)}
        material = _validated_material(data, context, constant_share, refresh_weight)
        write_json_atomic(path, data)
        return material


def stage_share(root: Path, context: MaterialContext, index: int, share: int, contributors: list[int]):
    if not 1 <= index <= context.n or type(share) is not int or not 0 < share < BABY_L:
        raise ValueError('Invalid candidate share')
    if not contributors or contributors != sorted(set(contributors)) or not all(1 <= i <= 20 for i in contributors):
        raise ValueError('Invalid authoritative contributor list')
    point = baby_mul(share)
    data = {'kind': 'zkdkg_v2_candidate_share', 'curve': 'BabyJubjub', 'context': asdict(context),
            'materialId': context.material_id, 'fileId': context.file_id, 'keyEpoch': context.epoch,
            'shareVersion': context.version, 'n': context.n, 't': context.t, 'index': index,
            'share': str(share), 'sk': str(share), 'vkx': str(point[0]), 'vky': str(point[1]),
            'computedFromOldIndices': contributors}
    directory = attempt_directory(root, context.material_id)
    with private_lock(directory):
        path = directory / f'candidate-{index}.json'
        if path.exists() or path.is_symlink():
            if read_private_json(path) != data:
                raise RuntimeError('Candidate share changed within one accepted attempt')
        else:
            write_json_atomic(path, data)
    return path


def activate_share(root: Path, context: MaterialContext, index: int, destination: Path, *, active_material_id):
    if material_id_bytes(active_material_id) != material_id_bytes(context.material_id):
        raise RuntimeError('Candidate attempt is not the active on-chain share version')
    if not 1 <= index <= context.n:
        raise ValueError('Invalid receiver index')
    if Path(destination).parent.resolve() == attempt_directory(root, context.material_id).resolve():
        raise ValueError('Active custody must be separate from pending attempt files')
    with private_lock(attempt_directory(root, context.material_id)):
        candidate = read_private_json(attempt_directory(root, context.material_id) / f'candidate-{index}.json')
        if candidate.get('context') != asdict(context) or candidate.get('index') != index:
            raise RuntimeError('Candidate share has the wrong activation context')
        share = int(candidate['share'])
        if not 0 < share < BABY_L or baby_mul(share) != (int(candidate['vkx']), int(candidate['vky'])):
            raise RuntimeError('Candidate share failed activation validation')
        final = {**candidate, 'kind': 'zkdkg_v2_final_share'}
        destination = Path(destination)
        # Old active files are never deleted. A different material ID at the
        # same destination requires explicit recovery, not an overwrite.
        with private_lock(destination.parent):
            if destination.exists() or destination.is_symlink():
                if read_private_json(destination) != final:
                    raise RuntimeError('Active share destination already contains different custody material')
            else:
                write_json_atomic(destination, final)
        return destination
