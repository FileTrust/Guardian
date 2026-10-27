"""Transaction-only JSONL logging for Guardian processes."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

_INSTALLED = False
_ORIGINAL_CALL = None
_ORIGINAL_ESTIMATE_GAS = None
_ORIGINAL_BUILD_TRANSACTION = None
_ORIGINAL_WAIT_RECEIPT = None
_ORIGINAL_SEND_RAW_TRANSACTION = None
_ORIGINAL_GET_TRANSACTION_COUNT = None
_ORIGINAL_GET_BLOCK = None
_ORIGINAL_BLOCK_NUMBER_PROP = None
_ORIGINAL_GET_CODE = None
_ORIGINAL_GET_BALANCE = None
_ORIGINAL_GET_LOGS = None
_ORIGINAL_GAS_PRICE_PROP = None
_TX_CONTEXT: dict[tuple[str, str, str, str], dict[str, Any]] = {}
_CURRENT_TX_LABEL = ""


def set_current_transaction_label(label: str = "") -> None:
    global _CURRENT_TX_LABEL
    _CURRENT_TX_LABEL = str(label or "")


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if hasattr(value, "hex"):
        return value.hex()
    return str(value)


def _iso_ts() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")



def default_log_path() -> Path:
    """Where this Guardian's transaction record lives: inside the Guardian.

    It used to default to reports/transaction_logs/, which only made sense
    because the test dashboard read from there. A Guardian has to be able to run
    on a machine of its own, so its records belong in its own instance folder.

    The protocol scripts run with CWD set to the instance root (G_1, G_2, ...),
    so ``logs/`` resolves per instance rather than being shared.
    """
    return Path.cwd() / "logs" / "g_transactions.jsonl"


def resolve_log_path(value: Any = "") -> Path:
    raw_text = str(value or "").strip()
    if not raw_text:
        return default_log_path()
    raw = Path(raw_text).expanduser()
    return raw if raw.is_absolute() else (Path.cwd() / raw).resolve()


def _context_get(context: Any, key: str, default: Any = "") -> Any:
    if isinstance(context, dict):
        return context.get(key, context.get(key.lower(), default))
    if hasattr(context, key):
        return getattr(context, key)
    if hasattr(context, key.lower()):
        return getattr(context, key.lower())
    if hasattr(context, key.upper()):
        return getattr(context, key.upper())
    return default


def context_log_path(context: Any = None) -> Path:
    return resolve_log_path(_context_get(context, "transaction_log_path", ""))


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, default=_json_default, separators=(",", ":")) + "\n")


def _chain_id(context: Any, w3: Any = None) -> str:
    if w3 is not None:
        try:
            return str(w3.eth.chain_id)
        except Exception:
            pass
    return str(_context_get(context, "chain_id", "") or "")


def _rpc_url(context: Any) -> str:
    return str(_context_get(context, "rpc_url", "") or "")


def _base(
    context: Any,
    *,
    tag: str,
    transaction_kind: str,
    actor_address: str,
    contract_name: str,
    function_name: str,
    contract_address: str,
    status: str,
    w3: Any = None,
) -> dict[str, Any]:
    return {
        "tag": tag,
        "facility": "guardian",
        "source": "G",
        "transaction_kind": transaction_kind,
        "network": "",
        "chain_id": _chain_id(context, w3),
        "timestamp": _iso_ts(),
        "rpc_url": _rpc_url(context),
        "actor_address": actor_address or "",
        "contract_name": contract_name or "",
        "function_name": function_name or "",
        "contract_address": contract_address or "",
        "to_address": contract_address or "",
        "value_wei": "0",
        "transaction_hash": "",
        "block_number": "",
        "status": status,
        "gas_used": "0",
        "gas_price_wei": "0",
        "effective_gas_price_wei": "0",
        "total_cost_wei": "0",
        "total_cost_eth": "0",
    }


def function_name(fn: Any, fallback: str = "") -> str:
    return str(getattr(fn, "fn_name", "") or getattr(fn, "function_identifier", "") or fallback or "")


def contract_address(fn: Any, fallback: str = "") -> str:
    return str(getattr(fn, "address", "") or fallback or "")


def request_id_from_function(fn: Any) -> int | None:
    """Best-effort extraction of requestId from bound contract function args."""
    fn_name = function_name(fn)
    try:
        args = list(getattr(fn, "args", []) or [])
    except Exception:
        args = []
    if not args:
        return None
    if fn_name in {
        "submitPrePartial",
        "submitV2AccessPartial",
        "submitV2BatchAccessPartial",
        "declareReadyForRequest",
        "signalPreReady",
        "expirePreRequest",
    }:
        try:
            return int(args[0])
        except Exception:
            return None
    return None


def contract_name_for_address(context: Any, address: str, fallback: str = "contract") -> str:
    target = str(address or "").lower()
    known = {
        "GuardianRegistry": _context_get(context, "guardian_registry_address", ""),
        "StakingManager": _context_get(context, "staking_manager_address", ""),
        "AccessControlFT": _context_get(context, "acl_address", ""),
        "DataVault": _context_get(context, "dv_address", ""),
        "TElG": _context_get(context, "telg_address", ""),
        "TElGv2": _context_get(context, "telg_v2_address", ""),
        "ZkDkgCoordinatorV2": _context_get(context, "zkdkg_coordinator_v2_address", ""),
        "ZkDkgDisputeManager": _context_get(context, "zkdkg_dispute_manager_address", ""),
        "GuardianShareProof": _context_get(context, "guardian_share_proof_address", ""),
        "ReputationManager": _context_get(context, "reputation_manager_address", ""),
        "RewardManager": _context_get(context, "reward_manager_address", ""),
        "ShareVerifier": _context_get(context, "zkdkg_share_verifier_address", ""),
        "V2PrePartialVerifier": _context_get(context, "v2_pre_partial_verifier_address", ""),
        "SharePossessionVerifier": _context_get(context, "share_possession_verifier_address", ""),
        "FileRegistrationSC": _context_get(context, "file_registration_address", ""),
    }
    for name, known_address in known.items():
        if str(known_address or "").lower() == target:
            return name
    return fallback


def log_eth_call(
    context: Any,
    *,
    contract_name: str,
    function_name: str,
    contract_address: str = "",
    actor_address: str = "",
    status: str,
    error: str = "",
    w3: Any = None,
    **details: Any,
) -> None:
    payload = _base(
        context,
        tag=f"g:{contract_name}.{function_name}",
        transaction_kind="eth_call",
        actor_address=actor_address,
        contract_name=contract_name,
        function_name=function_name,
        contract_address=contract_address,
        status=status,
        w3=w3,
    )
    payload.update({key: value for key, value in details.items() if value is not None})
    if error:
        payload["error"] = str(error)
    append_jsonl(context_log_path(context), payload)


def log_contract_transaction(
    context: Any,
    w3: Any,
    *,
    actor_address: str,
    contract_name: str,
    function_name: str,
    contract_address: str,
    tx: dict[str, Any],
    tx_hash: Any,
    receipt: Any,
    **details: Any,
) -> None:
    gas_used = int(receipt.get("gasUsed", 0) or 0)
    gas_price = int(tx.get("gasPrice", tx.get("gas_price", 0)) or 0)
    effective_gas_price = int(receipt.get("effectiveGasPrice", gas_price) or gas_price)
    total_cost_wei = gas_used * effective_gas_price
    payload = _base(
        context,
        tag=f"g:{contract_name}.{function_name}",
        transaction_kind="contract_transaction",
        actor_address=actor_address,
        contract_name=contract_name,
        function_name=function_name,
        contract_address=contract_address,
        status=str(receipt.get("status", "")),
        w3=w3,
    )
    payload.update(
        {
            "to_address": str(tx.get("to", "") or contract_address or ""),
            "value_wei": str(int(tx.get("value", 0) or 0)),
            "transaction_hash": tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash),
            "block_number": str(receipt.get("blockNumber", "")),
            "gas_used": str(gas_used),
            "gas_price_wei": str(gas_price),
            "effective_gas_price_wei": str(effective_gas_price),
            "total_cost_wei": str(total_cost_wei),
            "total_cost_eth": str(w3.from_wei(total_cost_wei, "ether")),
        }
    )
    claimed_reward_wei = _decode_claimed_reward_wei(w3, receipt, contract_name, function_name)
    if claimed_reward_wei:
        payload["claimed_reward_wei"] = claimed_reward_wei
    reward_credit = _decode_reward_credit_summary(w3, receipt)
    if reward_credit:
        payload.update(reward_credit)
    payload.update({key: value for key, value in details.items() if value is not None})
    append_jsonl(context_log_path(context), payload)


def log_contract_transaction_attempt(
    context: Any,
    *,
    actor_address: str,
    contract_name: str,
    function_name: str,
    contract_address: str,
    status: str,
    error: str = "",
    **details: Any,
) -> None:
    payload = _base(
        context,
        tag=f"g:{contract_name}.{function_name}",
        transaction_kind="contract_transaction_attempt",
        actor_address=actor_address,
        contract_name=contract_name,
        function_name=function_name,
        contract_address=contract_address,
        status=status,
    )
    payload.update({key: value for key, value in details.items() if value is not None})
    if error:
        payload["error"] = str(error)
    append_jsonl(context_log_path(context), payload)


def _tx_key(tx: dict[str, Any]) -> tuple[str, str, str, str]:
    data = tx.get("data", tx.get("input", "")) or ""
    if isinstance(data, bytes):
        data = "0x" + data.hex()
    elif hasattr(data, "hex"):
        data = data.hex()
        if not str(data).startswith("0x"):
            data = "0x" + str(data)
    return (
        str(tx.get("from", "") or "").lower(),
        str(tx.get("to", "") or "").lower(),
        str(tx.get("nonce", "") or ""),
        str(data).lower(),
    )


def _receipt_hash(receipt: Any, fallback: Any = "") -> Any:
    try:
        return receipt.get("transactionHash", fallback)
    except Exception:
        return fallback


def _hex_value(value: Any) -> str:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if hasattr(value, "hex"):
        text = value.hex()
        return text if str(text).startswith("0x") else "0x" + str(text)
    return str(value or "")


def _decode_claimed_reward_wei(w3: Any, receipt: Any, contract_name: str, function_name: str) -> str:
    if str(contract_name).lower() != "rewardmanager" or str(function_name).lower() != "claimrewards":
        return ""
    try:
        raw = w3.keccak(text="RewardsClaimed(address,uint256)").hex().lower()
        topic0 = raw if raw.startswith("0x") else "0x" + raw
    except Exception:
        return ""
    try:
        logs = receipt.get("logs", []) or []
    except Exception:
        logs = []
    for item in logs:
        topics = item.get("topics", []) if hasattr(item, "get") else []
        if not topics or _hex_value(topics[0]).lower() != topic0:
            continue
        try:
            return str(int(_hex_value(item.get("data", "0x")), 16))
        except Exception:
            return ""
    return ""


def _decode_reward_credit_summary(w3: Any, receipt: Any) -> dict[str, Any]:
    try:
        policy_topic = w3.keccak(
            text="GuardianMeasuredRewardCredited(bytes32,address,bytes32,uint256,uint256,uint256,uint256,uint256,uint256,uint256)"
        ).hex().lower()
        access_topic = w3.keccak(
            text="GuardianMeasuredAccessRewardCredited(uint256,bytes32,address,bytes32,uint256,uint256,uint256,uint256,uint256,uint256,uint256)"
        ).hex().lower()
    except Exception:
        return {}
    policy_topic = policy_topic if policy_topic.startswith("0x") else "0x" + policy_topic
    access_topic = access_topic if access_topic.startswith("0x") else "0x" + access_topic
    try:
        logs = receipt.get("logs", []) or []
    except Exception:
        logs = []

    policy_total = 0
    access_total = 0
    policy_count = 0
    access_count = 0
    reward_types: list[str] = []

    def words(data: Any) -> list[int]:
        text = _hex_value(data).replace("0x", "")
        if len(text) % 64:
            text = text.rjust(((len(text) // 64) + 1) * 64, "0")
        out = []
        for i in range(0, len(text), 64):
            chunk = text[i : i + 64]
            if chunk:
                out.append(int(chunk, 16))
        return out

    def topic_label(topic: Any) -> str:
        raw = _hex_value(topic).replace("0x", "")
        try:
            data = bytes.fromhex(raw).rstrip(b"\x00")
            return data.decode("utf-8", errors="ignore") or "0x" + raw
        except Exception:
            return "0x" + raw

    for item in logs:
        topics = item.get("topics", []) if hasattr(item, "get") else []
        if not topics:
            continue
        topic0 = _hex_value(topics[0]).lower()
        data_words = words(item.get("data", "0x")) if hasattr(item, "get") else []
        if topic0 == policy_topic and len(data_words) >= 7:
            policy_count += 1
            policy_total += data_words[6]
            if len(topics) >= 4:
                reward_types.append(topic_label(topics[3]))
        elif topic0 == access_topic and len(data_words) >= 8:
            access_count += 1
            access_total += data_words[7]
            reward_types.append(topic_label("0x" + f"{data_words[0]:064x}"))

    total = policy_total + access_total
    if total == 0:
        return {}
    source = "mixed"
    if policy_total and not access_total:
        source = "policy"
    elif access_total and not policy_total:
        source = "access"
    return {
        "reward_credit_amount_wei": str(total),
        "reward_credit_policy_wei": str(policy_total),
        "reward_credit_access_wei": str(access_total),
        "reward_credit_source": source,
        "reward_credit_count": str(policy_count + access_count),
        "reward_credit_types": ",".join(sorted(set(filter(None, reward_types)))),
    }


def install(context: Any) -> None:
    global _INSTALLED, _ORIGINAL_CALL, _ORIGINAL_ESTIMATE_GAS, _ORIGINAL_BUILD_TRANSACTION, _ORIGINAL_WAIT_RECEIPT, _ORIGINAL_SEND_RAW_TRANSACTION
    global _ORIGINAL_GET_TRANSACTION_COUNT, _ORIGINAL_GET_BLOCK, _ORIGINAL_BLOCK_NUMBER_PROP, _ORIGINAL_GET_CODE, _ORIGINAL_GET_BALANCE, _ORIGINAL_GET_LOGS, _ORIGINAL_GAS_PRICE_PROP
    if _INSTALLED:
        return
    try:
        from web3.contract.contract import ContractFunction
        from web3.eth.eth import Eth
    except Exception:
        return

    _ORIGINAL_CALL = ContractFunction.call
    _ORIGINAL_ESTIMATE_GAS = ContractFunction.estimate_gas
    _ORIGINAL_BUILD_TRANSACTION = ContractFunction.build_transaction
    _ORIGINAL_WAIT_RECEIPT = Eth.wait_for_transaction_receipt
    _ORIGINAL_SEND_RAW_TRANSACTION = Eth.send_raw_transaction
    _ORIGINAL_GET_TRANSACTION_COUNT = Eth.get_transaction_count
    _ORIGINAL_GET_BLOCK = Eth.get_block
    _ORIGINAL_BLOCK_NUMBER_PROP = Eth.block_number
    _ORIGINAL_GET_CODE = Eth.get_code
    _ORIGINAL_GET_BALANCE = Eth.get_balance
    _ORIGINAL_GET_LOGS = Eth.get_logs
    _ORIGINAL_GAS_PRICE_PROP = Eth.gas_price

    def logged_call(self, *args, **kwargs):
        fn_name = function_name(self)
        contract_addr = contract_address(self)
        c_name = contract_name_for_address(context, contract_addr)
        actor_address = ""
        tx_params = kwargs.get("transaction")
        if isinstance(tx_params, dict):
            actor_address = str(tx_params.get("from", "") or "")
        try:
            result = _ORIGINAL_CALL(self, *args, **kwargs)
            details: dict[str, Any] = {}
            if isinstance(result, (list, tuple)):
                details["result_count"] = len(result)
            log_eth_call(
                context,
                contract_name=c_name,
                function_name=fn_name,
                contract_address=contract_addr,
                actor_address=actor_address,
                status="success",
                **details,
            )
            return result
        except Exception as exc:
            log_eth_call(
                context,
                contract_name=c_name,
                function_name=fn_name,
                contract_address=contract_addr,
                actor_address=actor_address,
                status="failed",
                error=str(exc),
            )
            raise

    def logged_estimate_gas(self, *args, **kwargs):
        fn_name = function_name(self)
        contract_addr = contract_address(self)
        c_name = contract_name_for_address(context, contract_addr)
        request_id = request_id_from_function(self)
        actor_address = ""
        if args and isinstance(args[0], dict):
            actor_address = str(args[0].get("from", "") or "")
        tx_params = kwargs.get("transaction")
        if isinstance(tx_params, dict):
            actor_address = str(tx_params.get("from", "") or actor_address)
        try:
            gas = _ORIGINAL_ESTIMATE_GAS(self, *args, **kwargs)
            log_eth_call(
                context,
                contract_name="eth",
                function_name="estimateGas",
                contract_address=contract_addr,
                actor_address=actor_address,
                status="success",
                gas_estimate=gas,
                target_contract=c_name,
                target_function=fn_name,
                request_id=request_id,
            )
            return gas
        except Exception as exc:
            log_eth_call(
                context,
                contract_name="eth",
                function_name="estimateGas",
                contract_address=contract_addr,
                actor_address=actor_address,
                status="failed",
                error=str(exc),
                target_contract=c_name,
                target_function=fn_name,
                request_id=request_id,
            )
            raise

    def logged_build_transaction(self, *args, **kwargs):
        tx = _ORIGINAL_BUILD_TRANSACTION(self, *args, **kwargs)
        fn_name = function_name(self)
        contract_addr = contract_address(self, str(tx.get("to", "") or ""))
        c_name = contract_name_for_address(context, contract_addr)
        request_id = request_id_from_function(self)
        _TX_CONTEXT[_tx_key(tx)] = {
            "contract_name": c_name,
            "function_name": fn_name,
            "contract_address": contract_addr,
            "actor_address": str(tx.get("from", "") or ""),
        }
        if request_id is not None:
            _TX_CONTEXT[_tx_key(tx)]["request_id"] = int(request_id)
        if _CURRENT_TX_LABEL:
            _TX_CONTEXT[_tx_key(tx)]["label"] = _CURRENT_TX_LABEL
        return tx

    def logged_wait_for_receipt(self, tx_hash, *args, **kwargs):
        try:
            receipt = _ORIGINAL_WAIT_RECEIPT(self, tx_hash, *args, **kwargs)
        except Exception as exc:
            log_contract_transaction_attempt(
                context,
                actor_address="",
                contract_name="contract",
                function_name="wait_for_transaction_receipt",
                contract_address="",
                status="failed",
                error=str(exc),
                transaction_hash=tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash),
            )
            raise
        logged = False
        try:
            tx = dict(self.get_transaction(_receipt_hash(receipt, tx_hash)))
            meta = _TX_CONTEXT.get(_tx_key(tx), {})
            contract_addr = str(meta.get("contract_address") or tx.get("to", "") or "")
            c_name = str(meta.get("contract_name") or contract_name_for_address(context, contract_addr))
            fn_name = str(meta.get("function_name") or "unknown")
            log_contract_transaction(
                context,
                self.w3,
                actor_address=str(meta.get("actor_address") or tx.get("from", "") or ""),
                contract_name=c_name,
                function_name=fn_name,
                contract_address=contract_addr,
                tx=tx,
                tx_hash=_receipt_hash(receipt, tx_hash),
                receipt=receipt,
                label=meta.get("label", ""),
                request_id=meta.get("request_id"),
            )
            logged = True
        except Exception:
            logged = False
        if not logged:
            fallback_tx = {
                "to": "",
                "from": "",
                "value": 0,
                "gasPrice": int(receipt.get("effectiveGasPrice", 0) or 0),
            }
            log_contract_transaction(
                context,
                self.w3,
                actor_address="",
                contract_name="contract",
                function_name="unknown",
                contract_address="",
                tx=fallback_tx,
                tx_hash=_receipt_hash(receipt, tx_hash),
                receipt=receipt,
                metadata_lookup="failed",
            )
        return receipt

    def logged_send_raw_transaction(self, transaction, *args, **kwargs):
        try:
            return _ORIGINAL_SEND_RAW_TRANSACTION(self, transaction, *args, **kwargs)
        except Exception as exc:
            log_contract_transaction_attempt(
                context,
                actor_address="",
                contract_name="contract",
                function_name="send_raw_transaction",
                contract_address="",
                status="failed",
                error=str(exc),
            )
            raise

    def logged_get_transaction_count(self, account, *args, **kwargs):
        try:
            nonce = _ORIGINAL_GET_TRANSACTION_COUNT(self, account, *args, **kwargs)
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getTransactionCount",
                actor_address=str(account or ""),
                status="success",
                nonce=nonce,
                w3=self.w3,
            )
            return nonce
        except Exception as exc:
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getTransactionCount",
                actor_address=str(account or ""),
                status="failed",
                error=str(exc),
                w3=self.w3,
            )
            raise

    def logged_get_block(self, block_identifier, *args, **kwargs):
        try:
            block = _ORIGINAL_GET_BLOCK(self, block_identifier, *args, **kwargs)
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getBlock",
                actor_address="",
                status="success",
                block_identifier=block_identifier,
                block_number=block.get("number", ""),
                w3=self.w3,
            )
            return block
        except Exception as exc:
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getBlock",
                actor_address="",
                status="failed",
                error=str(exc),
                block_identifier=block_identifier,
                w3=self.w3,
            )
            raise

    def logged_block_number(self):
        try:
            number = _ORIGINAL_BLOCK_NUMBER_PROP.fget(self)
            log_eth_call(
                context,
                contract_name="eth",
                function_name="blockNumber",
                actor_address="",
                status="success",
                block_number=number,
                w3=self.w3,
            )
            return number
        except Exception as exc:
            log_eth_call(
                context,
                contract_name="eth",
                function_name="blockNumber",
                actor_address="",
                status="failed",
                error=str(exc),
                w3=self.w3,
            )
            raise

    def logged_get_code(self, account, *args, **kwargs):
        try:
            code = _ORIGINAL_GET_CODE(self, account, *args, **kwargs)
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getCode",
                contract_address=str(account or ""),
                status="success",
                code_size=len(code or b""),
                w3=self.w3,
            )
            return code
        except Exception as exc:
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getCode",
                contract_address=str(account or ""),
                status="failed",
                error=str(exc),
                w3=self.w3,
            )
            raise

    def logged_get_balance(self, account, *args, **kwargs):
        try:
            balance = _ORIGINAL_GET_BALANCE(self, account, *args, **kwargs)
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getBalance",
                actor_address=str(account or ""),
                status="success",
                result=balance,
                w3=self.w3,
            )
            return balance
        except Exception as exc:
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getBalance",
                actor_address=str(account or ""),
                status="failed",
                error=str(exc),
                w3=self.w3,
            )
            raise

    def logged_get_logs(self, filter_params, *args, **kwargs):
        try:
            entries = _ORIGINAL_GET_LOGS(self, filter_params, *args, **kwargs)
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getLogs",
                actor_address="",
                contract_address=str((filter_params or {}).get("address", "") if isinstance(filter_params, dict) else ""),
                status="success",
                result_count=len(entries or []),
                w3=self.w3,
            )
            return entries
        except Exception as exc:
            log_eth_call(
                context,
                contract_name="eth",
                function_name="getLogs",
                actor_address="",
                contract_address=str((filter_params or {}).get("address", "") if isinstance(filter_params, dict) else ""),
                status="failed",
                error=str(exc),
                w3=self.w3,
            )
            raise

    def logged_gas_price(self):
        try:
            value = _ORIGINAL_GAS_PRICE_PROP.fget(self)
            log_eth_call(
                context,
                contract_name="eth",
                function_name="gasPrice",
                actor_address="",
                status="success",
                result=value,
                w3=self.w3,
            )
            return value
        except Exception as exc:
            log_eth_call(
                context,
                contract_name="eth",
                function_name="gasPrice",
                actor_address="",
                status="failed",
                error=str(exc),
                w3=self.w3,
            )
            raise

    ContractFunction.call = logged_call
    ContractFunction.estimate_gas = logged_estimate_gas
    ContractFunction.build_transaction = logged_build_transaction
    Eth.send_raw_transaction = logged_send_raw_transaction
    Eth.wait_for_transaction_receipt = logged_wait_for_receipt
    Eth.get_transaction_count = logged_get_transaction_count
    Eth.get_block = logged_get_block
    Eth.block_number = property(logged_block_number)
    Eth.get_code = logged_get_code
    Eth.get_balance = logged_get_balance
    Eth.get_logs = logged_get_logs
    Eth.gas_price = property(logged_gas_price)
    _INSTALLED = True
