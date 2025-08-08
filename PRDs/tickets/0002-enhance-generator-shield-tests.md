# Ticket 0002: Enhance generator-shield test coverage

## Context
Generator-mode for `shield` was added to allow sync/async generator shields to act like per-endpoint middleware. Initial tests covered basic allow/block, teardown execution, exceptions, composition order, and injection. We want broader coverage to lock in behavior and avoid regressions.

## Goals
- Expand tests to cover additional edge cases and configurations for generator shields.
- Verify behavior with custom error/response settings, optional dependency parameters, validation errors during dependency resolution, nested failure scenarios, and guard parameter binding.
- Keep tests fast and deterministic.

## Test Requirements
Add tests to cover:
- auto_error=False path returning a custom default response; teardown runs.
- Custom `exception_to_raise_if_fail` is raised on falsy enter; teardown runs/closed.
- `ShieldedDepends` with optional first parameter: shield data not injected when first param has a default; dependency still resolves.
- Teardown runs even when request validation/dependency resolution fails (e.g., missing required query param) before endpoint body executes.
- HTTPException raised during generator enter propagates as-is.
- Falsy enter using `False` (not just `None`) blocks appropriately.
- Nested generator shields where inner blocks: outer teardown still runs; verify LIFO when multiple entered.
- Guard parameters via FastAPI-bound params (e.g., Header, Path) bind correctly to generator shield function.

## Acceptance Criteria
- New tests added and passing locally along with existing suite.
- No changes to public API.
- Tests clear and consistent with project style.
