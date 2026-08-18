---
name: python-engineering-standards
description: >-
  Enforces production-grade Python engineering patterns distilled from deep
  analysis of HTTPX, Rich, Stripe Python, and OpenAI Python codebases. Apply
  to every Python coding task. Covers module architecture, public API design,
  error hierarchies, typing discipline, resource lifecycle, and tooling. This
  is a foundational skill; framework-specific skills (Django, FastAPI) build
  on top of it without conflict.
---

# Python Engineering Standards

These standards are distilled from reverse-engineering four production Python
codebases — HTTPX, Rich, Stripe Python, and OpenAI Python — and extracting the
non-obvious patterns that make them feel effortless to read, safe to use, and
trivial to maintain. They were validated by applying them to a real SDK rewrite
(AgentSecrets v2 to v3: 62 files changed, 5,758 insertions).

This is NOT a list of "use type hints" or "write docstrings". These are the
structural and architectural patterns that separate a weekend project from a
codebase a senior engineer would approve in a design review.

> **Scope**: General Python — libraries, CLIs, services, SDKs. Framework-specific
> patterns (Django, FastAPI) belong in separate, additive skills that build on
> top of this one.

---

## 1. Module Architecture: The File IS The Abstraction

### 1.1 One Domain Concept Per File — No Dumping Grounds

Files named `utils.py`, `helpers.py`, `misc.py`, or `common.py` are
**prohibited**. Every file must be named after its single domain responsibility.

- URL parsing logic → `_urls.py`
- Multipart encoding → `_multipart.py`
- Exception definitions → `_exceptions.py` or `errors.py`
- Auth header construction → `_auth.py`

**Why this is non-obvious**: `utils.py` starts as 3 functions. Within 6 months
it's 400 lines of unrelated logic with circular import problems. The file IS the
abstraction boundary — naming it after the concept prevents scope creep because
new code that doesn't match the filename obviously doesn't belong there.

**Enforcement**: When you encounter or are about to create a `utils.py`,
`helpers.py`, `misc.py`, or `common.py`, STOP. Extract each function cluster
into a file named after what it does. If a function doesn't fit any named file,
that's a signal it may not be needed at all.

### 1.2 Inward-Only Import Flow

Imports must flow strictly downward/inward. Top-level public modules import
mid-level components, which import low-level primitives. Low-level primitives
never import high-level clients.

```text
High Level:   client.py / app.py
                    │
                    ▼
Mid Level:    models.py / auth.py / config.py
                    │
                    ▼
Low Level:    _transport.py / _encoding.py / errors.py
```

**Enforcement**: Before adding an import, check: "Am I importing from a
higher-level module into a lower-level one?" If yes, refactor. Extract the
shared concept into its own module at the correct level. Circular imports are a
design error, not a tooling problem.

### 1.3 Private Modules: `_` Prefix Convention

Internal implementation files get a `_` prefix (e.g. `_client.py`, `_auth.py`).
The public API re-exports from `__init__.py`. This convention tells users and
tools: "This file's internals are not part of the contract."

```python
# package/__init__.py
from ._client import Client
from ._models import Response

__all__ = ["Client", "Response"]
```

### 1.4 The 30-Line Function Guideline

Across HTTPX and Rich, the vast majority of functions fit within 20-40 lines.
This is not arbitrary — it means every function fits on one screen without
scrolling.

**The test**: If a function requires scrolling to read, it mixes levels of
abstraction. Split it. A high-level method delegates to lower-level methods. It
does not interleave configuration parsing with byte formatting.

---

## 2. Public API Boundary: Exports Are A Contract

### 2.1 Explicit `__all__` In Every `__init__.py`

Every package `__init__.py` MUST define `__all__`. This is the public API
contract. Anything not in `__all__` is an implementation detail that can change
without notice.

### 2.2 The `__module__` Patching Pattern

When a class is defined in `_client.py` but exported from `__init__.py`, its
`repr()`, tracebacks, and Sphinx docs show `package._client.Client` instead of
`package.Client`. Fix this:

```python
# package/__init__.py
from ._client import Client
from ._exceptions import PackageError

__all__ = ["Client", "PackageError"]

# Clean repr: package.Client instead of package._client.Client
for _export_name in __all__:
    if hasattr(locals()[_export_name], "__module__"):
        locals()[_export_name].__module__ = __name__
```

**Why this matters**: Users see `package.Client` in error messages and docs, not
leaked private module paths. This is what Stripe, OpenAI, and HTTPX all do.

### 2.3 `src/` Layout (PEP 561)

All new projects MUST use `src/` layout:

```text
project-name/
├── src/
│   └── package_name/
│       ├── __init__.py
│       ├── py.typed          # PEP 561 marker — ALWAYS include
│       ├── errors.py
│       └── ...
├── tests/
├── pyproject.toml
└── README.md
```

**Why `src/` layout**: It prevents the project root from shadowing the installed
package during testing. Without it, `import package` in tests might import the
source directory instead of the installed package, hiding packaging bugs that
only surface after `pip install`.

---

## 3. API Ergonomics: Signatures That Prevent Bugs

### 3.1 Keyword-Only Parameters (`*,`)

Every public constructor and method with more than one configuration parameter
MUST use keyword-only barriers:

```python
class Client:
    def __init__(
        self,
        *,                          # <-- Forces named arguments
        base_url: str = "",
        timeout: float = 30.0,
        retries: int = 0,
    ) -> None:
        ...
```

**Why**: `Client("https://api.com", True, 30)` is a bug waiting to happen.
`Client(base_url="https://api.com", timeout=30)` is self-documenting. All four
analysed codebases use this universally.

### 3.2 Sentinel Values vs `None` Ambiguity

When `None` is a valid user-provided value (meaning "disable this feature") AND
you also need a "not provided, use default" state, use an explicit sentinel:

```python
class _Unset:
    """Sentinel for distinguishing 'not provided' from None."""
    def __repr__(self) -> str:
        return "UNSET"

UNSET = _Unset()

def request(
    self,
    url: str,
    *,
    timeout: float | None | _Unset = UNSET,
) -> Response:
    if isinstance(timeout, _Unset):
        timeout = self._default_timeout
    # Now timeout=None genuinely means "no timeout"
```

**When NOT to use sentinels**: If `None` unambiguously means "use the default",
a sentinel adds unnecessary complexity. Use sentinels only when `None` itself
carries distinct meaning.

### 3.3 Flexible Inputs, Strict Outputs

Accept broad input types. Return narrow, precise types.

```python
# GOOD: Accept str or URL, always return URL
def resolve_url(url: str | URL) -> URL:
    ...

# BAD: Accept str, return str | dict | None depending on context
def resolve_url(url: str) -> str | dict | None:
    ...
```

### 3.4 `@overload` For Ambiguous Return Types

When a function's return type depends on an input parameter, use `@overload` so
the type checker and IDE know the exact return type at each call site:

```python
from typing import overload, Literal

@overload
def fetch(url: str, *, stream: Literal[True]) -> StreamResponse: ...
@overload
def fetch(url: str, *, stream: Literal[False] = ...) -> Response: ...

def fetch(url: str, *, stream: bool = False) -> StreamResponse | Response:
    ...
```

---

## 4. Error Architecture: Exceptions That Fix Themselves

### 4.1 Single Root Exception

Every package MUST define a single root exception that all package-specific
errors inherit from. This lets users write `except PackageError` to catch
everything from the package without catching unrelated `ValueError`s:

```python
class PackageError(Exception):
    """Base exception for all package errors."""
```

### 4.2 Diagnostic Context On Every Exception

Every exception class MUST carry structured diagnostic attributes beyond the
message string. The attributes depend on the error type but should include
everything needed to diagnose the problem without re-running the code:

```python
class APIError(PackageError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        response_body: str,
        url: str,
    ) -> None:
        self.status_code = status_code
        self.response_body = response_body
        self.url = url
        super().__init__(message)
```

### 4.3 Actionable Fix Hints

When an exception has a known resolution, embed it as a `fix_hint` that renders
in the traceback. This is critical for AI agents and junior developers who
cannot intuit the fix from the error alone:

```python
class PackageError(Exception):
    def __init__(self, message: str, *, fix_hint: str | None = None) -> None:
        self.message = message
        self.fix_hint = fix_hint
        full = f"{message}\n  Fix: {fix_hint}" if fix_hint else message
        super().__init__(full)

class NotInstalledError(PackageError):
    def __init__(self) -> None:
        super().__init__(
            "The 'tool' binary was not found on PATH.",
            fix_hint="pip install tool",
        )
```

### 4.4 Hierarchy Mirrors Domain Failure Modes

Do not create exceptions for HTTP status codes. Create exceptions for domain
failure modes:

```text
PackageError
├── ConnectionError     (can't reach the service)
├── AuthError           (credentials rejected)
├── NotFoundError       (resource doesn't exist)
├── PermissionError     (insufficient role/scope)
└── UpstreamError       (service reached, but it failed)
```

---

## 5. Resource Lifecycle: Context Managers Are Not Optional

### 5.1 Dual Context Manager Protocol

Any class that holds resources (connections, file handles, subprocesses,
connection pools) MUST implement:

1. `__enter__` / `__exit__` (sync)
2. `__aenter__` / `__aexit__` (async, if async variant exists)
3. Explicit `close()` / `aclose()` for non-context-manager usage

```python
class Client:
    def __init__(self, ...) -> None:
        self._is_closed = False

    def __enter__(self) -> Client:
        if self._is_closed:
            raise RuntimeError("Cannot reuse a closed client.")
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._is_closed:
            self._is_closed = True
            self._transport.close()
```

### 5.2 Closed-State Guard

Every method that uses the managed resource MUST check `_is_closed` and raise
`RuntimeError` if the client has been closed. This prevents subtle bugs where a
closed client silently returns stale data or hangs.

---

## 6. Sync/Async Architecture: Mirror Without Duplication

### 6.1 Symmetric Client Split

If a project needs both sync and async, provide two separate client classes:
`Client` and `AsyncClient`. Never mix `sync_method()` and `async_method()` on
the same class.

### 6.2 Shared Core Logic

Factor business logic into a shared base or private module. The sync and async
clients differ only in their transport/IO layer. They should share validation,
serialization, URL construction, header building — everything except the actual
network call.

```text
_base.py         → Shared: validation, headers, URL building, serialization
client.py        → Sync:  calls self._transport.send(request)
async_client.py  → Async: calls await self._transport.send(request)
```

---

## 7. Typing Discipline: Strict By Default

### 7.1 `from __future__ import annotations` In Every File

This makes all annotations strings (PEP 563), enabling forward references and
`X | Y` union syntax on older Python versions. Put it as the first import in
every `.py` file.

### 7.2 `mypy --strict` As Baseline

`pyproject.toml` MUST enable strict mode:

```toml
[tool.mypy]
strict = true
warn_return_any = true
disallow_any_generics = true
```

### 7.3 No `Any` Escape Hatches Without Comment

Every use of `Any` must have an inline comment explaining why the type cannot be
narrowed. `Any` is a code smell — sometimes necessary, never silent.

```python
# Any required: json.loads returns arbitrary structure from external input
data: Any = json.loads(response.body)
```

### 7.4 `TypedDict` For Structured Dictionaries

Never pass `dict[str, Any]` for structured data. Define a `TypedDict`:

```python
from typing import TypedDict

class RequestOptions(TypedDict, total=False):
    timeout: float
    retries: int
    headers: dict[str, str]
```

---

## 8. Testing Architecture

### 8.1 Official `testing/` Subpackage

If the package is a client library, provide a `testing/` subpackage with mock
transports and test helpers that users import in their own test suites:

```python
# package/testing/__init__.py
from ._mock_client import MockClient
from ._fixtures import mock_response

__all__ = ["MockClient", "mock_response"]
```

Users write:
```python
from mypackage.testing import MockClient
```

**Why**: Without this, every consumer reinvents mock setup. Providing official
test utilities ensures consistent mocking behavior across the ecosystem.

### 8.2 Test Parity: Sync and Async

If the package has both sync and async clients, every test case MUST have both a
sync and async variant. Do not test only the sync path and assume async works.

---

## 9. Tooling: `pyproject.toml` As Single Source Of Truth

### 9.1 Unified Configuration

All tool configuration lives in `pyproject.toml`. No `setup.cfg`, no `setup.py`,
no `.flake8`, no `.isort.cfg`, no `mypy.ini` as separate files.

```toml
[project]
name = "package-name"
version = "1.0.0"
requires-python = ">=3.10"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.ruff]
target-version = "py310"
line-length = 88

[tool.ruff.lint]
select = ["E", "W", "F", "I", "UP", "B", "SIM", "TCH"]

[tool.mypy]
strict = true
```

### 9.2 Ruff Replaces Everything

Use Ruff for linting AND formatting. It replaces flake8, isort, black, pyflakes,
and pycodestyle in a single tool that runs in milliseconds.

### 9.3 Hatchling or Flit As Build Backend

Use modern PEP 517 build backends. `setuptools` with `setup.py` is legacy.

---

## 10. Anti-Patterns Checklist

Before finalizing any Python code, verify NONE of these are present:

| Anti-Pattern | Why It's Bad | Fix |
|:---|:---|:---|
| `utils.py` / `helpers.py` | Becomes a junk drawer | Name files after domain concepts |
| Positional args for config | `Client("url", True, 30)` is unreadable | Use `*,` keyword-only barriers |
| `**kwargs` on public API | Destroys autocomplete and type checking | Enumerate parameters explicitly |
| `except Exception: pass` | Silently swallows real bugs | Catch specific exceptions, log or re-raise |
| God class with 50+ methods | Untestable, unreadable | Split into focused sub-clients or modules |
| `Any` without comment | Invisible type hole | Annotate why `Any` is unavoidable |
| Missing `close()` on clients | Resource leaks in long-running processes | Implement context manager protocol |
| `setup.py` | Legacy, non-declarative | Migrate to `pyproject.toml` + hatchling |
| `import *` | Pollutes namespace, hides dependencies | Use explicit imports |
| Global mutable state | Thread-unsafe, test-hostile | Pass config through constructor arguments |
| Metaclass magic for API | Breaks IDE autocomplete and static analysis | Use explicit class definitions |
| Builder/Factory patterns | Python has kwargs and defaults already | Use keyword-only constructors |

---

## Enforcement Protocol

When working on any Python codebase, apply these standards as follows:

1. **New files**: Apply all standards from the start. No exceptions.
2. **Existing files being modified**: Apply standards to the code you touch.
   Do not refactor adjacent code unless explicitly asked.
3. **New projects**: Scaffold with `src/` layout, `pyproject.toml`, `py.typed`,
   explicit `__all__`, and `mypy --strict` from day one.
4. **Code review**: Flag violations of these standards in review feedback. Focus
   on the high-impact patterns (dumping grounds, missing `__all__`, positional
   args on constructors, missing context managers, silent `Any`).

> **Composability note**: This skill defines foundational Python patterns.
> Framework-specific skills (Django Ninja, FastAPI, Flask) should ADD patterns
> on top of these — never contradict them. For example, a Django skill might add
> "use `APIView` classes over function views" but would never say "use
> `setup.py`" because this skill already mandates `pyproject.toml`.
