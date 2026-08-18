---
name: django-ninja-engineering-standards
description: >-
  Enforces production-grade architecture, design patterns, and engineering
  standards for Django Ninja backends. Distilled from deep analysis of Django
  Ninja framework internals, FastAPI comparative architecture, and real-world
  production fintech applications (paycore-api-1). Builds directly ON TOP of
  the foundational 'python-engineering-standards' skill without conflict. Covers
  thin controllers, services vs selectors, Pydantic schemas, database N+1
  prevention, SQL-level pagination, async safety, transaction boundaries,
  and background task post-commit guarantees.
---

# Django Ninja Production Engineering Standards

This skill governs the design, implementation, code review, and refactoring of
production-grade Python backends built with **Django Ninja**.

It builds directly ON TOP OF the foundational **`python-engineering-standards`**
skill. General Python standards (PEP 561, `pyproject.toml`, explicit `__all__`,
Ruff, strict typing, sentinel values, no `utils.py` dumping grounds) remain
fully mandatory. This skill defines their **Django- and Django Ninja-specific
application, extension, and architectural enforcement**.

---

## 1. Core Architecture & Layering Model

Django Ninja applications MUST adhere to strict separation of concerns:

```text
HTTP Request
    │
    ▼
1. Django Ninja Router (urls & tags)
    │
    ▼
2. Authentication & Security Guards (HttpBearer / AuthUser)
    │
    ▼
3. Request Schema Validation (Pydantic / Ninja Schema)
    │
    ▼
4. Endpoint Controller (Thin View Function — < 25 LOC)
    │
    ├── Mutating Actions ────► 5a. Domain Service Layer (Atomic Transactions, Business Rules)
    │                                │
    │                                ├──► PostgreSQL Database (select_for_update, ORM)
    │                                └──► Post-Commit Tasks (transaction.on_commit)
    │
    └── Read Queries ────────► 5b. Selector Layer (select_related, prefetch_related, pure reads)
                                     │
                                     └──► PostgreSQL Database (SQL LIMIT/OFFSET)
    │
    ▼
6. Response Schema Serialization (from_attributes / CustomResponse envelope)
    │
    ▼
HTTP Response (Explicit Status Code)
```

---

## 2. Mandatory Rules (Enforcement Checklist)

### 2.1 The Thin Controller Mandate
- **Rule**: Endpoint view functions MUST be thin adapters (< 25 lines). They must only unpack request parameters, authenticate, invoke a single Service or Selector, and return the response.
- **Violation**: Writing ORM queries, complex loops, multi-table transactions, password hashing, or external HTTP calls directly inside `@router` view functions.
- **Enforcement**: Move all business logic to `services/` and read queries to `selectors.py`.

### 2.2 Explicit Response Schemas on Every Route
- **Rule**: Every operation MUST declare explicit response schemas with HTTP status codes: `@router.get(..., response={200: ItemSchema, 404: ErrorSchema})`.
- **Violation**: Returning untyped Python `dict`s or omitting the `response` argument.
- **Why**: Untyped returns break OpenAPI contract generation and bypass Pydantic field-filtering.

### 2.3 Strict Schema Sourcing & No `fields = "__all__"`
- **Rule**: `ModelSchema` MUST NEVER use `fields = "__all__"`. Always enumerate explicit fields.
- **Rule**: Request payloads MUST forbid extra fields (`model_config = ConfigDict(extra="forbid")`).
- **Violation**: Exposing database models directly or allowing mass-assignment of arbitrary JSON fields.

### 2.4 N+1 Query Elimination
- **Rule**: Any endpoint returning collections or nested objects MUST use `.select_related()` (for `ForeignKey`/`OneToOne`) and `.prefetch_related()` (for `ManyToManyField`/reverse relations).
- **Violation**: Iterating over querysets where child relations trigger separate SQL queries per row during schema serialization.

### 2.5 True SQL-Level Pagination
- **Rule**: Pagination MUST evaluate SQL `LIMIT` and `OFFSET` on the QuerySet (`queryset[offset : offset + limit]`).
- **Violation**: Converting querysets to in-memory lists `list(queryset)` before slicing. On large tables, this exhausts server RAM and causes gateway timeouts.

### 2.6 Safe Async & Transaction Boundaries
- **Rule**:
  - In `async def` views, database access MUST use async ORM methods (`aget()`, `acreate()`, `aexists()`, `acount()`) or be wrapped with `sync_to_async`.
  - Transactional logic (`transaction.atomic()`) MUST be encapsulated in synchronous service functions called via `await sync_to_async(Service.execute)()`.
- **Violation**: Calling blocking synchronous ORM methods directly in async event loops or using unsafe async transaction hacks.

### 2.7 Background Task Post-Commit Guarantee
- **Rule**: Celery or async background tasks triggered from code within a database transaction MUST be dispatched via `transaction.on_commit(lambda: task.delay(...))`.
- **Violation**: Calling `task.delay()` inside `transaction.atomic()`. This causes worker race conditions where tasks run before database changes are committed.

### 2.8 Centralized Error Translation
- **Rule**: Raise typed domain exceptions (`RequestError`, `NotFoundError`, `PermissionDeniedError`) and let `@api.exception_handler` format uniform JSON errors.
- **Violation**: Catching exceptions with manual `try/except` in every view to return custom error responses.

---

## 3. Code Review & Verification Rubric

When reviewing or generating Django Ninja code, verify each item:

| Check | Requirement | Action if Failed |
| :--- | :--- | :--- |
| **Endpoint Size** | View function < 25 LOC | Extract logic to `services.py` / `selectors.py` |
| **Response Schema** | `response={200: ...}` present | Define explicit Pydantic response schema |
| **Schema Security** | No `fields = "__all__"` | Enumerate allowed fields explicitly |
| **Query Efficiency** | `select_related` on foreign keys | Add pre-fetching to selector queries |
| **Pagination** | SQL `LIMIT/OFFSET` used | Replace in-memory list slices with DB slices |
| **Task Safety** | `transaction.on_commit()` used | Wrap Celery `.delay()` calls in `on_commit` |
| **Error Handling** | Global exception handlers | Raise custom exceptions, remove view `try/except` |
| **Param Sourcing** | Explicit `Path(...)`, `Query(...)` | Annotate all operation parameters explicitly |

---

## 4. Architectural Reference Artifacts

For complete guides, deep rationale, and full blueprints, refer to:
- [`DJANGO_NINJA_PRODUCTION_ENGINEERING_GUIDE.md`](file:///C:/Users/steppa/.gemini/antigravity/brain/ff007546-fbff-4ab7-b67e-518a9e35d770/DJANGO_NINJA_PRODUCTION_ENGINEERING_GUIDE.md)
- [`DJANGO_NINJA_ENGINEERING_STANDARDS.md`](file:///C:/Users/steppa/.gemini/antigravity/brain/ff007546-fbff-4ab7-b67e-518a9e35d770/DJANGO_NINJA_ENGINEERING_STANDARDS.md)
- [`DJANGO_NINJA_ARCHITECTURE_BLUEPRINT.md`](file:///C:/Users/steppa/.gemini/antigravity/brain/ff007546-fbff-4ab7-b67e-518a9e35d770/DJANGO_NINJA_ARCHITECTURE_BLUEPRINT.md)
