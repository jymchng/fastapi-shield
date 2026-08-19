"""
Rate limiting + LLM API-credits budgeting example for fastapi-shield.

This example demonstrates two reusable shields for LLM-powered APIs:

1. ``rate_limit_shield`` — a 5-hour sliding-window rate limit.
   Blocks requests with HTTP 429 Too Many Requests when the client
   exceeds ``MAX_REQUESTS_PER_5_HOURS`` within a rolling 5-hour window.

2. ``credits_budget_shield`` — an LLM API-credits budget.
   Estimates the credit cost of each LLM call from the *prompt* tokens
   (request body) plus the *completion* tokens (estimated from the requested
   ``max_tokens``). 1 token == 1 credit. When the per-client budget is
   exhausted, requests are blocked with HTTP 402 Payment Required.

Both shields use ``exception_to_raise_if_fail`` so clients receive a clear
HTTP status instead of the default 500.

Run it directly (self-tests at the bottom):

    python examples/llm-budgeting/main.py

Or via pytest:

    python -m pytest examples/llm-budgeting/main.py
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from fastapi_shield import shield

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# --- 5-hour rate limit ---
RATE_LIMIT_WINDOW_SECONDS = 5 * 60 * 60  # 5 hours
MAX_REQUESTS_PER_5_HOURS = 10

# --- LLM credits budget ---
CREDIT_BUDGET_PER_CLIENT = 1000  # total credits each client can spend
TOKENS_PER_CREDIT = 1  # 1 token == 1 credit


# ---------------------------------------------------------------------------
# In-memory stores (use Redis/DB in production)
# ---------------------------------------------------------------------------

# client_key -> list of request timestamps within the rolling window
_request_timestamps: Dict[str, List[float]] = defaultdict(list)

# client_key -> remaining credits
_remaining_credits: Dict[str, float] = defaultdict(lambda: float(CREDIT_BUDGET_PER_CLIENT))


def _client_key(request: Request) -> str:
    """Identify the client (IP by default; use API keys/user IDs in prod)."""
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Shields
# ---------------------------------------------------------------------------


@shield(
    name="5-Hour Rate Limit",
    auto_error=True,
    exception_to_raise_if_fail=HTTPException(
        status_code=429,
        detail="Rate limit exceeded: too many requests within a 5-hour window.",
    ),
)
def rate_limit_shield(request: Request):
    """
    Sliding-window rate limit: allow at most ``MAX_REQUESTS_PER_5_HOURS``
    requests per client in a rolling 5-hour window.
    """
    key = _client_key(request)
    now = time.time()

    # Keep only timestamps inside the rolling 5-hour window
    timestamps = [
        ts for ts in _request_timestamps[key] if now - ts < RATE_LIMIT_WINDOW_SECONDS
    ]
    _request_timestamps[key] = timestamps

    if len(timestamps) >= MAX_REQUESTS_PER_5_HOURS:
        return None  # blocked -> HTTP 429

    _request_timestamps[key].append(now)
    return True  # allowed


def _estimate_tokens(text: str) -> int:
    """Cheap token estimate: ~4 characters per token."""
    return max(1, len(text) // 4)


@shield(
    name="LLM Credits Budget",
    auto_error=True,
    exception_to_raise_if_fail=HTTPException(
        status_code=402,
        detail="Insufficient API credits: LLM credits budget exhausted.",
    ),
)
async def credits_budget_shield(request: Request):
    """
    LLM API-credits budgeting: each call costs
    ``prompt_tokens + completion_tokens`` credits (1 token == 1 credit).

    - prompt tokens are estimated from the request body prompt;
    - completion tokens are estimated from the requested ``max_tokens``
      (worst case). In production, replace the completion estimate with the
      actual ``usage.completion_tokens`` returned by your LLM provider and
      reconcile after each call.
    """
    key = _client_key(request)

    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    prompt = str(body.get("prompt", "") or "")
    max_tokens = int(body.get("max_tokens", 256) or 256)

    prompt_tokens = _estimate_tokens(prompt)
    completion_tokens = max(1, max_tokens)  # worst-case completion estimate
    cost = (prompt_tokens + completion_tokens) * TOKENS_PER_CREDIT

    if _remaining_credits[key] < cost:
        return None  # blocked -> HTTP 402

    _remaining_credits[key] -= cost
    return True  # allowed


# ---------------------------------------------------------------------------
# Mocked LLM layer
# ---------------------------------------------------------------------------


def generate_llm_reply(prompt: str, max_tokens: int = 256) -> str:
    """Stand-in for a real LLM call (OpenAI/Anthropic/...)."""
    return f"Echo: {prompt}"[: max_tokens * 4]


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(title="LLM Budgeting Example")


@app.post("/llm/chat")
@rate_limit_shield
@credits_budget_shield
async def llm_chat(payload: Dict[str, Any], request: Request):
    """
    LLM endpoint protected by:
      1. ``rate_limit_shield``   -> 429 when the 5-hour window is exceeded
      2. ``credits_budget_shield`` -> 402 when the credits budget is exhausted
    """
    prompt: str = str(payload.get("prompt", ""))
    max_tokens: int = int(payload.get("max_tokens", 256))

    completion = generate_llm_reply(prompt, max_tokens)

    return {
        "reply": completion,
        "credits_remaining": _remaining_credits[_client_key(request)],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

client = TestClient(app)


def _reset_state() -> None:
    """Reset the in-memory stores so each test starts fresh."""
    _request_timestamps.clear()
    _remaining_credits.clear()


def test_rate_limit_allows_within_window() -> None:
    _reset_state()
    for _ in range(MAX_REQUESTS_PER_5_HOURS):
        resp = client.post("/llm/chat", json={"prompt": "Hello", "max_tokens": 16})
        assert resp.status_code == 200, resp.json()


def test_rate_limit_blocks_after_5_hour_window() -> None:
    _reset_state()
    for _ in range(MAX_REQUESTS_PER_5_HOURS):
        resp = client.post("/llm/chat", json={"prompt": "Hello", "max_tokens": 16})
        assert resp.status_code == 200, resp.json()
    # The (N+1)-th request within the same window -> 429
    resp = client.post("/llm/chat", json={"prompt": "Hello", "max_tokens": 16})
    assert resp.status_code == 429, resp.json()
    assert "rate limit" in resp.json()["detail"].lower()


def test_rate_limit_window_expires() -> None:
    _reset_state()
    for _ in range(MAX_REQUESTS_PER_5_HOURS):
        client.post("/llm/chat", json={"prompt": "Hello", "max_tokens": 16})
    # Simulate 5 hours passing so the window slides
    now = time.time()
    for key in _request_timestamps:
        _request_timestamps[key] = [
            ts - RATE_LIMIT_WINDOW_SECONDS for ts in _request_timestamps[key]
        ]
    resp = client.post("/llm/chat", json={"prompt": "Hello", "max_tokens": 16})
    assert resp.status_code == 200, resp.json()


def test_credits_deducted_per_call() -> None:
    _reset_state()
    resp1 = client.post("/llm/chat", json={"prompt": "Hello world", "max_tokens": 32})
    assert resp1.status_code == 200, resp1.json()
    remaining_1 = resp1.json()["credits_remaining"]
    resp2 = client.post("/llm/chat", json={"prompt": "Hello world", "max_tokens": 32})
    assert resp2.status_code == 200, resp2.json()
    remaining_2 = resp2.json()["credits_remaining"]
    assert remaining_2 < remaining_1  # credits were deducted per call


def test_credits_budget_exhausted_returns_402() -> None:
    _reset_state()
    # Each call here costs (100 prompt tokens + 32 completion) = 132 credits.
    # With a budget of 1000, the budget is exhausted after a few calls.
    saw_402 = False
    for _ in range(20):
        resp = client.post("/llm/chat", json={"prompt": "x" * 400, "max_tokens": 32})
        if resp.status_code == 402:
            saw_402 = True
            break
    assert saw_402, "expected the budget to be exhausted within 20 calls"
    # The next call is still blocked with 402
    resp = client.post("/llm/chat", json={"prompt": "x" * 400, "max_tokens": 32})
    assert resp.status_code == 402, resp.json()
    assert "credits" in resp.json()["detail"].lower()


def test_shielded_endpoint_stacks_both() -> None:
    _reset_state()
    resp = client.post("/llm/chat", json={"prompt": "Hi", "max_tokens": 8})
    assert resp.status_code == 200, resp.json()
    assert "reply" in resp.json()
    assert "credits_remaining" in resp.json()


def run_tests() -> None:
    for name, fn in list(globals().items()):
        if callable(fn) and name.startswith("test_"):
            fn()
            print(f"  PASS {name}")


if __name__ == "__main__":
    print("Running llm-budgeting example tests...")
    run_tests()
    print("All tests passed!")
