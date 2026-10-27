"""What the access policy says right now.

Kept free of configuration so the rule can be tested without a Guardian
identity -- importing the chain module requires a real private key, which a test
about policy state has no business needing. Same reason g_chain_logs.py and
g_secret_files.py exist.
"""
from __future__ import annotations

from web3 import Web3


def get_current_policy_info(acl, file_id_bytes) -> dict:
    """Read the live policy, refusing to proceed if it is gone or switched off.

    The Guardian takes the guardian set and the threshold from here. Reading
    them while ignoring whether the policy is still active would mean serving a
    policy its owner had revoked -- and revocation that a Guardian does not
    notice is not revocation.
    """
    exists, active, owner, threshold, guardians = acl.functions.getFilePolicy(file_id_bytes).call()
    if not exists or not active:
        raise RuntimeError("PRE: file policy does not exist or is inactive")
    current_guardians = [Web3.to_checksum_address(g) for g in guardians]
    return {"threshold": int(threshold), "guardians": current_guardians, "n": len(current_guardians)}


# A guardian set larger than this is not a policy anyone can serve: the Guardian
# would fetch and verify a share from every member before it could compute
# anything. Generous next to any real committee, and small enough that a
# nonsense value cannot turn one policy into an afternoon of work.
MAX_GUARDIANS = 256


def policy_parameters_are_safe(n: int, t: int) -> tuple[bool, str]:
    """Is this a threshold worth taking part in?

    A Guardian is not obliged to serve every set of numbers the chain offers.
    Two of them are refusals rather than errors:

    A threshold of one means a single Guardian alone reconstructs the key. That
    is not a weaker version of threshold cryptography, it is its absence, and
    the Guardian holding that share is then a single point of compromise for
    someone else's file -- and the obvious person to blame when it leaks.

    A threshold above the guardian count can never be met, so participating
    means dealing shares into a key nobody will ever assemble.

    Refusing is a real cost: a Guardian that does not take part may be recorded
    as absent. It is still the right answer, because the alternative is holding
    a share under terms the system was built to prevent.
    """
    try:
        n_i, t_i = int(n), int(t)
    except (TypeError, ValueError):
        return False, f"policy parameters are not numbers: n={n!r}, t={t!r}"

    if n_i < 2:
        return False, f"a guardian set of {n_i} cannot be a threshold policy"
    if n_i > MAX_GUARDIANS:
        return False, f"guardian set of {n_i} exceeds the {MAX_GUARDIANS} this Guardian will serve"
    if t_i <= 1:
        return False, (
            f"threshold {t_i} means one Guardian alone reconstructs the key; "
            f"refusing to hold a share on those terms"
        )
    if t_i > n_i:
        return False, f"threshold {t_i} can never be met by {n_i} guardians"
    return True, "ok"


def select_next_policy(policies: list, cursor: int) -> tuple[object, int]:
    """Take one policy to work on, and move the cursor past it.

    The legacy path services one policy per pass and always took the first. If
    that one fails every time -- unreadable on-chain data, a peer that never
    answers, anything -- the pass ends there and the next pass takes the same
    one again. Every other policy this Guardian serves is starved for as long as
    the bad one exists, and the Guardian is recorded as absent for all of them.

    That is cheap to arrange on purpose. Whoever creates a policy chooses its
    file id, so they choose where it sorts, and one poisoned entry near the
    front is enough.

    Rotating gives every policy its turn regardless. A policy that always fails
    then costs one pass each round instead of all of them.
    """
    if not policies:
        return None, 0
    index = int(cursor) % len(policies)
    return policies[index], index + 1
