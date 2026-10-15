"""Pay refuses a second p tag and a hash already paid or in flight."""

from __future__ import annotations

import inspect
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_bitcoin.client import AgentBitcoinClient
from agent_bitcoin.models import InvoiceQuote
from agent_bitcoin.payment_attempts import begin_attempt

_PAID = "ab" * 32


def _client(mock_lnd: MagicMock) -> AgentBitcoinClient:
    with patch("agent_bitcoin.client.LNDClient", return_value=mock_lnd):
        return AgentBitcoinClient()


def _lnd(
    *,
    payment_hash: str = _PAID,
    amount: str = "2000",
    success: bool = True,
    decode_error: BaseException | None = None,
) -> MagicMock:
    mock_lnd = MagicMock()
    if decode_error is not None:
        mock_lnd.decode_pay_req.side_effect = decode_error
    else:
        mock_lnd.decode_pay_req.return_value = {
            "num_satoshis": amount,
            "payment_hash": payment_hash,
        }
    mock_lnd.pay_invoice.return_value = MagicMock(
        success=success,
        payment_hash=payment_hash,
        amount=int(amount),
        status="SUCCEEDED" if success else "FAILED",
    )
    return mock_lnd


def test_fee_limit_and_expiry_defaults_unchanged() -> None:
    pay = inspect.signature(AgentBitcoinClient.pay_invoice)
    quote = inspect.signature(AgentBitcoinClient.pay_invoice_quote)
    create = inspect.signature(AgentBitcoinClient.create_invoice)
    assert pay.parameters["fee_limit_sats"].default == 200
    assert quote.parameters["routing_fee_limit_sats"].default == 200
    assert create.parameters["expiry_seconds"].default == 3600


def test_lnd_image_pin_unchanged() -> None:
    root = Path(__file__).resolve().parents[1]
    pins: list[str] = []
    paths = list(root.glob("docker-compose*.yml"))
    paths.append(root / "examples" / "client-pack" / "docker-compose.yml")
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "lightninglabs/lnd:" in line:
                pins.append(line.strip())
    assert pins
    for line in pins:
        assert "lightninglabs/lnd:v0.18.5-beta" in line


def test_second_pay_of_paid_hash_refused(clear_payment_env) -> None:
    mock_lnd = _lnd()
    client = _client(mock_lnd)
    first = client.pay_invoice("lntbs20u1test")
    assert first.success is True
    with pytest.raises(ValueError, match="payment already recorded: succeeded"):
        client.pay_invoice("lntbs20u1other")
    mock_lnd.pay_invoice.assert_called_once()


def test_in_flight_hash_is_not_retried(clear_payment_env) -> None:
    begin_attempt(_PAID)
    mock_lnd = _lnd()
    client = _client(mock_lnd)
    with pytest.raises(ValueError, match="payment already recorded: in_flight"):
        client.pay_invoice("lntbs20u1test")
    mock_lnd.pay_invoice.assert_not_called()


def test_failed_pay_stays_in_flight(clear_payment_env) -> None:
    mock_lnd = _lnd(success=False)
    client = _client(mock_lnd)
    result = client.pay_invoice("lntbs20u1test")
    assert result.success is False
    with pytest.raises(ValueError, match="payment already recorded: in_flight"):
        client.pay_invoice("lntbs20u1again")
    mock_lnd.pay_invoice.assert_called_once()


def test_decode_failure_does_not_pay(clear_payment_env) -> None:
    mock_lnd = _lnd(decode_error=RuntimeError("lnd down"))
    client = _client(mock_lnd)
    with pytest.raises(ValueError, match="payment_hash_unknown"):
        client.pay_invoice("lntbs20u1test")
    mock_lnd.pay_invoice.assert_not_called()


def test_duplicate_p_refused_before_pay(clear_payment_env) -> None:
    pytest.importorskip("bolt11")
    from tests.test_ln_invoice_decode import _HASH, _invoice_duplicate_payment_hash

    raw = _invoice_duplicate_payment_hash()
    mock_lnd = _lnd(payment_hash=_HASH, amount="1000")
    client = _client(mock_lnd)
    with pytest.raises(ValueError, match="duplicate_payment_hash"):
        client.pay_invoice(raw)
    mock_lnd.decode_pay_req.assert_not_called()
    mock_lnd.pay_invoice.assert_not_called()


def test_single_p_invoice_still_pays(clear_payment_env) -> None:
    pytest.importorskip("bolt11")
    from tests.test_ln_invoice_decode import _HASH, _invoice

    raw = _invoice()
    mock_lnd = _lnd(payment_hash=_HASH, amount="1000")
    client = _client(mock_lnd)
    result = client.pay_invoice(raw, fee_limit_sats=200)
    assert result.success is True
    mock_lnd.pay_invoice.assert_called_once()
    assert mock_lnd.pay_invoice.call_args.kwargs["fee_limit_sats"] == 200


def test_hash_mismatch_refuses_pay(clear_payment_env) -> None:
    pytest.importorskip("bolt11")
    from tests.test_ln_invoice_decode import _invoice

    raw = _invoice()
    mock_lnd = _lnd(payment_hash="dd" * 32, amount="1000")
    client = _client(mock_lnd)
    with pytest.raises(ValueError, match="payment_hash_mismatch"):
        client.pay_invoice(raw)
    mock_lnd.pay_invoice.assert_not_called()


def test_quote_pay_refuses_hash_already_paid(clear_payment_env) -> None:
    mock_lnd = _lnd()
    client = _client(mock_lnd)
    assert client.pay_invoice("lntbs20u1test").success is True
    quote = InvoiceQuote(
        payment_request="lntbs20u1quote",
        amount_sats=2000,
        total_cost_sats=2000,
    )
    with pytest.raises(ValueError, match="payment already recorded: succeeded"):
        client.pay_invoice_quote(quote)
    mock_lnd.pay_invoice.assert_called_once()
