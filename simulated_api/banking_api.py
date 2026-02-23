import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, List, Optional


logger = logging.getLogger("simulated_banking_api")


class BankingError(Exception):
    pass


class AccountNotFoundError(BankingError):
    def __init__(self, account_id: str) -> None:
        super().__init__(f"Account not found: {account_id}")
        self.account_id = account_id


class InsufficientFundsError(BankingError):
    def __init__(self, account_id: str, available: Decimal, required: Decimal) -> None:
        super().__init__(f"Insufficient funds for {account_id}")
        self.account_id = account_id
        self.available = available
        self.required = required


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _money(value: Any) -> Decimal:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise BankingError("Invalid amount") from exc
    if d <= 0:
        raise BankingError("Amount must be positive")
    return d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


@dataclass(frozen=True)
class Transaction:
    transaction_id: str
    created_at: str
    currency: str
    amount: str
    sender_account: str
    receiver_account: str
    status: str
    reference: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


_lock = threading.RLock()
_balances: Dict[str, Decimal] = {
    # Seed accounts for local testing
    "acc_1001": Decimal("25000.00"),
    "acc_2001": Decimal("1500.00"),
    "acc_3001": Decimal("875.25"),
}
_transactions: List[Transaction] = []


def get_balance(account_id: str) -> Decimal:
    with _lock:
        if account_id not in _balances:
            raise AccountNotFoundError(account_id)
        return _balances[account_id]


def transfer_money(
    *,
    sender_account: str,
    receiver_account: str,
    amount: Any,
    currency: str = "USD",
    reference: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Transaction:
    amt = _money(amount)
    ccy = (currency or "USD").upper()
    if len(ccy) != 3:
        raise BankingError("Invalid currency")

    with _lock:
        if sender_account not in _balances:
            raise AccountNotFoundError(sender_account)
        if receiver_account not in _balances:
            raise AccountNotFoundError(receiver_account)

        available = _balances[sender_account]
        if available < amt:
            raise InsufficientFundsError(sender_account, available=available, required=amt)

        _balances[sender_account] = (available - amt).quantize(Decimal("0.01"))
        _balances[receiver_account] = (_balances[receiver_account] + amt).quantize(
            Decimal("0.01")
        )

        txn = Transaction(
            transaction_id=f"txn_{uuid.uuid4().hex}",
            created_at=_now_iso(),
            currency=ccy,
            amount=str(amt),
            sender_account=sender_account,
            receiver_account=receiver_account,
            status="COMPLETED",
            reference=reference,
            metadata=metadata or {},
        )
        _transactions.append(txn)

    logger.info(
        "transfer_completed",
        extra={
            "transaction_id": txn.transaction_id,
            "sender_account": sender_account,
            "receiver_account": receiver_account,
            "amount": str(amt),
            "currency": ccy,
        },
    )
    return txn


def list_transactions(limit: int = 50) -> List[Transaction]:
    with _lock:
        return list(_transactions[-max(1, int(limit)) :])


def process_transfer(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Backwards-compatible entry point used by the gateway.

    Expected payload shape (from SecureTransferRequest):
    - source_account
    - destination_account
    - amount
    - currency
    - metadata
    """
    try:
        txn = transfer_money(
            sender_account=str(payload.get("source_account")),
            receiver_account=str(payload.get("destination_account")),
            amount=payload.get("amount"),
            currency=str(payload.get("currency") or "USD"),
            reference=str(payload.get("reference")) if payload.get("reference") else None,
            metadata=payload.get("metadata") or {},
        )
        return {
            "transaction_id": txn.transaction_id,
            "status": "completed",
            "provider": "simulated_banking_api",
            "transaction": asdict(txn),
        }
    except BankingError as exc:
        logger.warning(
            "transfer_failed",
            extra={
                "error": exc.__class__.__name__,
                "detail": str(exc),
            },
        )
        return {
            "transaction_id": f"txn_{uuid.uuid4().hex}",
            "status": "failed",
            "provider": "simulated_banking_api",
            "error": exc.__class__.__name__,
            "detail": str(exc),
        }

