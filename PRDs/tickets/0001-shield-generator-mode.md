# Ticket 0001: Make `shield` support generator-mode (per-endpoint middleware)

## Context
`Shield` in `src/fastapi_shield/shield.py` is a decorator that intercepts a request before the endpoint, runs a user-provided `shield_func`, and either allows the request (truthy return) or blocks (falsy return). Today, `shield` supports sync/async callables that return a value.

We want to extend `shield` to also support a generator-based pattern (sync and async generators) so that a single shield can act like per-endpoint middleware: run logic before the endpoint executes and optionally run teardown/cleanup logic after the endpoint returns, while preserving all existing capabilities (dependency injection, `ShieldedDepends`, OpenAPI signature handling, error behavior, etc.). This should allow patterns like timing, resource acquisition/release, audit logging, or context vars setup/cleanup around a single endpoint.

## Goals
- Add support for generator-based shields that behave similarly to FastAPI/Dependency generator dependencies and Starlette middleware.
- Maintain backwards compatibility for current sync/async non-generator shields and tests.
- Allow usage as a decorator on a single endpoint; multiple shields can still compose.
- Generator shields should still be able to return/truth-test the yielded “enter” value to allow/block and supply data to `ShieldedDepends`.
- On exit (after endpoint completion), the shield’s generator `finally`/`yield`-after section should run even if the endpoint raised an exception (mirrors dependency generators), with access to relevant context if feasible.

## Non-Goals
- No global app-wide middleware registration; this feature is scoped to per-endpoint behavior via the decorator.
- No change to public import surface beyond the new capability; keep `shield` and `Shield` names.

## User-facing Design
Two valid shield shapes:
1. Value-returning shield (existing):
```python
@shield
async def auth_shield(request: Request) -> dict | None:
    user = await authenticate(request)
    return user  # truthy to allow, falsy to block
```

2. Generator shield (new):
- Async generator:
```python
@shield
async def audit_shield(request: Request):
    start = monotonic()
    # pre-logic; returning a truthy enter value allows the request
    enter_value = {"start": start}
    # If you want to block, yield a falsy value and return early
    try:
        result = yield enter_value
    finally:
        duration = monotonic() - start
        await audit_log(request, duration)
```
- Sync generator:
```python
@shield
def resource_shield():
    resource = acquire()
    try:
        yield {"resource": resource}
    finally:
        release(resource)
```
Behavioral rules:
- Before the endpoint executes, execute the generator to first `yield` and obtain an "enter" value.
- If enter value is falsy, block according to `auto_error`/defaults.
- If truthy, inject into `ShieldedDepends` just like current value-returning shields.
- After endpoint completion (success or exception), resume/finalize the generator to run teardown.
- If the generator raises during enter or finalize with a non-HTTPException, translate into a 500 just like current shields; HTTPException should propagate.

## Technical Requirements
- Detect callable kinds: plain sync, plain async, sync generator, async generator.
  - Reuse `fastapi.dependencies.utils.is_coroutine_callable` and detect generators via `inspect.isgeneratorfunction` and `inspect.isasyncgenfunction`.
- Wrapper should:
  - For generator shields:
    - Instantiate generator (`gen = guard_func(**guard_func_args)`), then advance to first `yield` to get `enter_value` (`await anext(gen)` for async variant; `next(gen)` for sync variant).
    - Truth-test `enter_value`; if falsy, close the generator (`gen.aclose()` or `gen.close()`) and block via `_raise_or_return_default_response`.
    - If truthy: resolve endpoint dependencies and `ShieldedDepends` with `enter_value` (same as today), call endpoint, then always finalize the generator in a `finally` block (async: `await gen.aclose()`; sync: `gen.close()`).
  - For value-returning shields: retain current path unchanged.
- Ensure teardown runs even if endpoint raises; propagate endpoint exceptions after teardown.
- Preserve `wrapper.__signature__` manipulation for OpenAPI (unchanged); generator shields must still expose the same call-time parameters.
- Preserve storage of `SHIELDED_ENDPOINT_PATH_FORMAT_KEY` and injection behavior.
- Update error handling to include generator enter/finalize errors mirroring existing behavior: wrap non-HTTPException into HTTP 500 with `detail=f"Shield with name `{self.name}` failed: {e}"`.

## Edge Cases & Compatibility
- Multiple shields composition: each generator shield’s teardown must only run if its enter succeeded (i.e., after yielding a truthy value). If a preceding shield blocks, subsequent shields are not executed.
- Ensure `ShieldedDepends` keeps working with truthy enter value piped as first arg when required.
- Async endpoint + sync generator shield, and vice versa should both work; wrapper stays async.
- If a generator yields a mapping intended for injection but the endpoint has no `ShieldedDepends`, behavior is still allow/teardown-only.

## Tests (must add; existing tests must pass)
Add new tests exercising generator shields:
- `tests/test_generator_shield_basic.py`
  - Async generator shield allows request, teardown runs (e.g., record audit log list) even on success.
  - Falsy enter value blocks with default 500, and generator is closed (teardown may or may not run depending on design; here we will close without running teardown body beyond generator close semantics).
  - Exception in generator enter path -> HTTP 500 with message.
  - Exception in teardown path -> HTTP 500 after endpoint completes.
- `tests/test_generator_shield_sync.py`
  - Sync generator shield acquiring resource and releasing it in `finally` runs release after endpoint.
  - Verify `ShieldedDepends` receives enter value.
- `tests/test_generator_shield_composition.py`
  - Multiple shields including mix of generator and non-generator; verify ordering and that each teardown runs in LIFO order only for shields that entered.
- `tests/test_generator_shield_errors.py`
  - Ensure HTTPException from generator enter propagates as-is.
  - Ensure non-HTTPException maps to 500 with the standardized detail string.

Notes:
- Tests should use `TestClient` and mirror existing style in `tests/test_examples_*` for consistency.
- Keep test runtime minimal; avoid sleeps; use in-memory lists/flags to assert teardown execution.

## Acceptance Criteria
- New generator-mode supported for both sync and async shields.
- All existing tests remain green.
- New tests above added and green.
- Documentation updated in `docs/api/shield.md` and `docs/api/shield-factory.md` with generator examples and behavior notes.
- No API breaking changes; imports remain `from fastapi_shield import shield, Shield, ShieldedDepends`.
