"""Operator limits checked before a Guardian signs a funded DKG acceptance.

No wallet/config reads and no transaction submission. The worker supplies
authoritative contract fields; an RPC error is not an empty/zero-valued offer.
"""
from __future__ import annotations

from dataclasses import dataclass


def _integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f'Invalid DKG acceptance setting: {name}')
    return value


@dataclass(frozen=True)
class AcceptanceLimits:
    enabled: bool
    max_bond_wei: int
    min_acceptance_fee_wei: int
    min_material_fee_wei: int
    min_share_key_fee_wei: int
    max_concurrent_attempts: int
    min_material_window_seconds: int
    min_receiver_window_seconds: int
    max_work_duration_seconds: int
    max_dispute_duration_seconds: int = 3600

    @classmethod
    def from_config(cls, settings):
        if not isinstance(settings, dict):
            raise ValueError('DKG acceptance settings must be an object')
        enabled = settings.get('enabled', False)
        if type(enabled) is not bool:
            raise ValueError('DKG acceptance enabled must be true or false')
        if not enabled:
            return cls(False, 0, 0, 0, 0, 1, 60, 60, 3600)
        # Deliberate opt-in terms. Missing limits never mean unlimited bond or
        # willingness to fund all work for free. Installer UX is a later gate.
        required = ['max_bond_wei', 'min_acceptance_fee_wei', 'min_material_fee_wei', 'min_share_key_fee_wei']
        if any(name not in settings for name in required):
            raise ValueError('Set DKG collateral and minimum fees before enabling acceptance')
        values = [_integer(settings[name], name) for name in required]
        concurrent = _integer(settings.get('max_concurrent_attempts', 1), 'max_concurrent_attempts', 1)
        if concurrent > 64:
            raise ValueError('DKG concurrency limit exceeds 64')
        material = _integer(settings.get('min_material_window_seconds', 60), 'min_material_window_seconds', 1)
        receiver = _integer(settings.get('min_receiver_window_seconds', 60), 'min_receiver_window_seconds', 1)
        maximum = _integer(settings.get('max_work_duration_seconds', 3600), 'max_work_duration_seconds', 1)
        dispute = _integer(settings.get('max_dispute_duration_seconds', 3600), 'max_dispute_duration_seconds', 1)
        if maximum > 172800 or material + receiver > maximum:
            raise ValueError('Invalid DKG work duration bounds')
        if dispute>172800:raise ValueError('Invalid DKG dispute response duration bound')
        return cls(True, *values, concurrent, material, receiver, maximum, dispute)


@dataclass(frozen=True)
class DutyOffer:
    n: int
    t: int
    dealer: bool
    receiver: bool
    bond_wei: int
    acceptance_fee_wei: int
    material_fee_wei: int
    share_key_fee_wei: int
    material_window_seconds: int
    receiver_window_seconds: int
    dispute_duration_seconds: int = 3600


def acceptance_decision(limits: AcceptanceLimits, offer: DutyOffer, *, installed_profiles,
                        active_attempts: int, available_stake_wei: int, wallet_fee_balance_wei: int,
                        estimated_acceptance_cost_wei: int, profile_verified: bool):
    if not limits.enabled:
        return False, 'DKG acceptance is disabled; configure its collateral and fee limits first'
    if any(type(v) is not int or v < 0 for v in [offer.n, offer.t, offer.bond_wei, offer.acceptance_fee_wei,
            offer.material_fee_wei, offer.share_key_fee_wei, offer.material_window_seconds,
            offer.receiver_window_seconds, offer.dispute_duration_seconds, active_attempts, available_stake_wei,
            wallet_fee_balance_wei, estimated_acceptance_cost_wei]):
        raise ValueError('Invalid authoritative DKG offer or balance')
    if type(offer.dealer) is not bool or type(offer.receiver) is not bool or not (offer.dealer or offer.receiver):
        return False, 'This Guardian has no assigned duty'
    if not 2 <= offer.t <= offer.n <= 20 or (offer.n, offer.t) not in installed_profiles or profile_verified is not True:
        return False, 'The exact proof profile and frozen verifier must be installed and verified'
    if offer.bond_wei > limits.max_bond_wei:
        return False, 'The requested collateral exceeds the operator limit'
    if offer.bond_wei > available_stake_wei:
        return False, 'Insufficient unreserved stake for this duty'
    if active_attempts >= limits.max_concurrent_attempts:
        return False, 'The accepted job limit is reached'
    if wallet_fee_balance_wei < estimated_acceptance_cost_wei:
        return False, 'Insufficient wallet balance for the acceptance transaction'
    if offer.acceptance_fee_wei < limits.min_acceptance_fee_wei:
        return False, 'The acceptance fee is below the operator minimum'
    if offer.dealer and offer.material_fee_wei < limits.min_material_fee_wei:
        return False, 'The material fee is below the operator minimum'
    if offer.receiver and offer.share_key_fee_wei < limits.min_share_key_fee_wei:
        return False, 'The share confirmation fee is below the operator minimum'
    if (not offer.dealer and offer.material_fee_wei != 0) or (not offer.receiver and offer.share_key_fee_wei != 0):
        return False, 'The quote includes work outside this Guardian duty'
    if offer.material_window_seconds < limits.min_material_window_seconds or offer.receiver_window_seconds < limits.min_receiver_window_seconds:
        return False, 'The accepted work windows are too short'
    if offer.material_window_seconds + offer.receiver_window_seconds > limits.max_work_duration_seconds:
        return False, 'The requested work duration exceeds the operator limit'
    if not 1<=offer.dispute_duration_seconds<=limits.max_dispute_duration_seconds:
        return False, 'The dispute response duration exceeds the operator limit'
    return True, 'The offer is within operator limits'
