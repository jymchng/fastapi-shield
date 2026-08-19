# LLM Budgeting Example 🧠💸

Shield your LLM-powered FastAPI endpoints from runaway **usage** and **costs**
with two composable `fastapi-shield` shields:

| Shield | What it protects | HTTP status when blocked |
|---|---|---|
| `rate_limit_shield` | **5-hour sliding-window rate limit** (max N requests per client per rolling 5h) | `429 Too Many Requests` |
| `credits_budget_shield` | **LLM API-credits budget** — each call costs `prompt_tokens + completion_tokens` credits (1 token = 1 credit) | `402 Payment Required` |

Both shields are applied with a single line each:

```python
@app.post("/llm/chat")
@rate_limit_shield
@credits_budget_shield
async def llm_chat(payload: dict):
    ...
```

## How the credits are estimated 🧮

- **Prompt tokens**: estimated from the request body prompt (≈ 4 chars/token).
- **Completion tokens**: in this example the mocked LLM layer records the
  generated completion so the shield can price it *before* the endpoint runs.
  In production, read `usage.prompt_tokens` / `usage.completion_tokens` from
  your LLM provider's response (OpenAI, Anthropic, etc.).

## Run it 🚀

```bash
# Self-testing script (runs the TestClient tests)
python examples/llm-budgeting/main.py

# Or via pytest
python -m pytest examples/llm-budgeting/main.py

# Or via the repo's nox runner
uv tool run nox -s run-examples -- llm-budgeting/main.py
```

## What the tests prove ✅

- Requests within the 5-hour window succeed (`200`).
- The request that crosses the 5-hour limit is blocked (`429`).
- After the window slides, requests succeed again (`200`).
- Exhausting the credit budget blocks the next call (`402`).
- Credits are deducted per call.
- Both shields stack cleanly on one endpoint.

> **Note:** the stores are in-memory (`defaultdict`). Use Redis or a database
> for multi-worker deployments.
