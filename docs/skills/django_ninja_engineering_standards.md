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

### The 5 Architectural Layers

| Layer | File / Location | Responsibility | Forbidden Inside This Layer |
| :--- | :--- | :--- | :--- |
| **1. Controllers (Views)** | `apps/{domain}/views.py` | Sourcing HTTP params (`Path`, `Query`, `Header`), auth gating, invoking service/selector, returning status code. | Raw SQL/ORM queries, business loops, calculations, password hashing, third-party network calls. |
| **2. Schemas (Contracts)** | `apps/{domain}/schemas.py` | Input validation (`extra="forbid"`), output serialization, API wire format definitions. | Direct database operations, ORM mutations, stateful business logic. |
| **3. Selectors (Queries)** | `apps/{domain}/selectors.py` | Read-only query building, query optimization (`select_related`, `prefetch_related`), aggregations. | State mutations, DB inserts/updates/deletes, transaction locking, side effects. |
| **4. Services (Mutations)** | `apps/{domain}/services.py` | Business logic, state transitions, atomic transactions (`transaction.atomic()`), row locking (`select_for_update()`), post-commit task dispatch. | Direct HTTP parsing, request/response headers, raw session manipulation. |
| **5. Models (Persistence)** | `apps/{domain}/models.py` | Database schema, constraints (`CheckConstraint`, `UniqueConstraint`), field indexes, pure local properties (`is_expired`). | Cross-model queries, external network requests, Celery task triggering. |

---

## 2. Mandatory Rules (Enforcement Standards)

### Rule 2.1: The Thin Controller Mandate (MUST)
- **Rule**: Endpoint view functions MUST be thin adapters (< 25 lines). They must only unpack request parameters, authenticate, invoke a single Service or Selector, and return the response.
- **Violation**: Writing ORM queries, complex loops, multi-table transactions, password hashing, or external HTTP calls directly inside `@router` view functions.
- **Good Example**:
  ```python
  @router.post("/links", response={201: PaymentLinkResponseSchema})
  async def create_payment_link(request, payload: CreatePaymentLinkSchema):
      user = request.auth
      link = await sync_to_async(PaymentLinkService.create_link)(user=user, data=payload)
      return CustomResponse.success("Payment link created", link, status_code=201)
  ```
- **Bad Example**:
  ```python
  @router.post("/links")
  async def create_payment_link(request, payload: CreatePaymentLinkSchema):
      # 60 lines of wallet checks, slug generation, email sending, and DB writes directly in view!
  ```

---

### Rule 2.2: Explicit Response Schemas on Every Route (MUST)
- **Rule**: Every API operation MUST declare explicit response schemas with HTTP status code keys in the `response={...}` decorator argument.
- **Violation**: Returning untyped Python `dict`s or omitting the `response` argument.
- **Why**: Untyped returns break OpenAPI contract generation, bypass Pydantic field-filtering, and risk leaking sensitive model attributes.
- **Good Example**:
  ```python
  @router.get("/{wallet_id}", response={200: WalletResponseSchema, 404: ErrorResponseSchema})
  async def get_wallet(request, wallet_id: UUID = Path(...)):
      ...
  ```

---

### Rule 2.3: Strict Schema Sourcing & No `fields = "__all__"` (MUST)
- **Rule**: `ModelSchema` MUST NEVER use `fields = "__all__"`. Always enumerate explicit fields.
- **Rule**: Request payloads MUST forbid extra fields (`model_config = ConfigDict(extra="forbid")`).
- **Why**: When new sensitive columns (e.g. `hashed_password`, `internal_notes`, `is_blocked`) are added to models via migrations, `fields = "__all__"` automatically exposes them to public API clients without review.
- **Good Example**:
  ```python
  class UserProfileSchema(ModelSchema):
      class Meta:
          model = User
          fields = ["id", "first_name", "last_name", "email", "avatar_url"]
  ```

---

### Rule 2.4: N+1 Query Elimination via Pre-Fetching (MUST)
- **Rule**: Any endpoint returning collections or nested objects MUST use `.select_related()` (for `ForeignKey`/`OneToOne`) and `.prefetch_related()` (for `ManyToManyField`/reverse relations).
- **Why**: Django Ninja iterates over queryset records and accesses nested attributes during Pydantic serialization. Without pre-fetching, this triggers a separate SQL query for each row ($N+1$).
- **Good Example**:
  ```python
  @router.get("/cards", response=List[CardResponseSchema])
  async def list_cards(request):
      qs = Card.objects.filter(user=request.auth).select_related("wallet", "wallet__currency")
      return await sync_to_async(list)(qs)
  ```

---

### Rule 2.5: True SQL-Level Pagination (MUST)
- **Rule**: Pagination MUST evaluate SQL `LIMIT` and `OFFSET` directly on the QuerySet (`queryset[offset : offset + limit]`).
- **Violation**: Converting querysets to in-memory lists `list(queryset)` before slicing. On large tables, this exhausts server RAM and causes gateway timeouts.
- **Good Example**:
  ```python
  def paginate_queryset(queryset, page: int = 1, limit: int = 50):
      total = queryset.count()
      offset = (page - 1) * limit
      items = list(queryset[offset : offset + limit])
      return {"items": items, "total": total, "page": page, "limit": limit}
  ```

---

### Rule 2.6: Safe Async & Transaction Boundaries (MUST)
- **Rule**:
  - In `async def` views, database access MUST use async ORM methods (`aget()`, `acreate()`, `aexists()`, `acount()`) or be wrapped with `sync_to_async`.
  - Transactional logic (`transaction.atomic()`) MUST be encapsulated in synchronous service functions called via `await sync_to_async(Service.execute)()`.
- **Violation**: Calling blocking synchronous ORM methods directly in async event loops or using unsafe async transaction hacks.

---

### Rule 2.7: Background Task Post-Commit Guarantee (MUST)
- **Rule**: Celery or async background tasks triggered from code within a database transaction MUST be dispatched via `transaction.on_commit(lambda: task.delay(...))`.
- **Violation**: Calling `task.delay()` inside `transaction.atomic()`. This causes worker race conditions where tasks run before database changes are committed, raising `DoesNotExist` errors.
- **Good Example**:
  ```python
  with transaction.atomic():
      order = Order.objects.create(...)
      transaction.on_commit(lambda: process_order_task.delay(order.id))
  ```

---

### Rule 2.8: Centralized Error Translation (MUST)
- **Rule**: Raise typed domain exceptions (`RequestError`, `NotFoundError`, `PermissionDeniedError`) and let `@api.exception_handler` format uniform JSON errors.
- **Violation**: Catching exceptions with manual `try/except` in every view to return custom error responses.
- **Good Example**:
  ```python
  # In service / selector:
  if not wallet:
      raise NotFoundError("Wallet not found")
  if wallet.balance < amount:
      raise BodyValidationError("amount", "Insufficient funds")
  ```

---

## 3. Reference Architecture & Implementation Blueprint

### 3.1 Recommended Repository Structure

```text
my_backend/
├── pyproject.toml                     # Single source of truth (ruff, mypy, hatchling)
├── Dockerfile                         # Multi-stage production container build
├── docker-compose.yml                 # Local Postgres, Redis, Celery
├── conftest.py                        # Root Pytest fixtures & mock infrastructure
├── core/                              # Project configuration & orchestration
│   ├── asgi.py                        # ASGI entrypoint
│   ├── wsgi.py                        # WSGI entrypoint
│   ├── celery.py                      # Celery app initialization
│   ├── urls.py                        # Root Django URL routing
│   ├── api.py                         # Root NinjaAPI instance, security & exception handlers
│   └── settings/
│       ├── base.py                    # Shared apps, middleware, logging, DB
│       ├── dev.py                     # Local development overrides
│       └── prod.py                    # Production security headers, Sentry, Redis
└── apps/                              # Domain-driven Django applications
    ├── common/                        # System-wide primitives & cross-cutting concerns
    │   ├── models.py                  # Abstract BaseModel with UUID and timestamps
    │   ├── exceptions.py              # Root RequestError and ErrorCode definitions
    │   ├── paginators.py              # SQL LIMIT/OFFSET paginator
    │   └── responses.py               # Uniform JSON envelope (CustomResponse)
    ├── accounts/                      # Auth, User profiles, Credentials
    │   ├── models.py
    │   ├── schemas.py
    │   ├── auth.py                    # HttpBearer authenticators (AuthUser, AuthAdmin)
    │   ├── services.py
    │   ├── selectors.py
    │   └── views.py
    └── payments/                      # Payments, Checkout, Invoices
        ├── models.py
        ├── schemas.py
        ├── services/                  # PaymentProcessor, InvoiceManager
        ├── selectors.py
        └── views.py
```

---

### 3.2 Core Component Blueprints

#### Base Model (`apps/common/models.py`)
```python
import uuid
from django.db import models

class GetOrNoneQuerySet(models.QuerySet):
    def get_or_none(self, **kwargs):
        try:
            return self.get(**kwargs)
        except self.model.DoesNotExist:
            return None

    async def aget_or_none(self, **kwargs):
        try:
            return await self.aget(**kwargs)
        except self.model.DoesNotExist:
            return None

class BaseModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = GetOrNoneQuerySet.as_manager()

    class Meta:
        abstract = True
        ordering = ["-created_at"]
```

#### Atomic Domain Service (`apps/payments/services/payment_processor.py`)
```python
from decimal import Decimal
from uuid import UUID
from django.db import transaction
from apps.common.exceptions import BodyValidationError
from apps.wallets.models import Wallet
from apps.payments.models import Payment, PaymentStatus
from apps.notifications.tasks import send_payment_notification

class PaymentProcessor:
    @staticmethod
    def process_payment(*, user, wallet_id: UUID, amount: Decimal) -> Payment:
        with transaction.atomic():
            # 1. Row-level locking to prevent race conditions / double-spending
            wallet = Wallet.objects.select_for_update().select_related("currency").get(
                id=wallet_id, user=user
            )

            # 2. Domain validation
            if wallet.balance < amount:
                raise BodyValidationError("amount", "Insufficient wallet funds")

            # 3. State mutation
            wallet.balance -= amount
            wallet.save(update_fields=["balance", "updated_at"])

            payment = Payment.objects.create(
                user=user,
                wallet=wallet,
                amount=amount,
                status=PaymentStatus.COMPLETED,
            )

            # 4. Safe post-commit task dispatch
            transaction.on_commit(lambda: send_payment_notification.delay(payment.id))

            return payment
```

#### The Query Selector (`apps/payments/selectors.py`)
```python
from uuid import UUID
from apps.common.exceptions import NotFoundError
from apps.payments.models import Payment

class PaymentSelector:
    @staticmethod
    async def get_by_id(*, user, payment_id: UUID) -> Payment:
        payment = await Payment.objects.select_related(
            "wallet", "wallet__currency"
        ).aget_or_none(id=payment_id, user=user)

        if not payment:
            raise NotFoundError("Payment record not found")
        return payment
```

---

## 4. Code Review & Verification Rubric

When reviewing or generating Django Ninja code, verify every line against this checklist:

| Category | Requirement | Severity | Action if Failed |
| :--- | :--- | :--- | :--- |
| **Controllers** | View function < 25 LOC | `MUST` | Extract logic to `services.py` or `selectors.py` |
| **Contracts** | `response={200: ...}` present on all operations | `MUST` | Define explicit Pydantic response schema |
| **Security** | No `fields = "__all__"` on `ModelSchema` | `MUST` | Enumerate allowed fields explicitly |
| **Security** | Request schemas use `extra = "forbid"` | `MUST` | Add `model_config = ConfigDict(extra="forbid")` |
| **Performance** | `select_related` / `prefetch_related` on nested queries | `MUST` | Add pre-fetching to prevent N+1 queries |
| **Performance** | SQL `LIMIT/OFFSET` used in pagination | `MUST` | Replace in-memory list slices with DB slices |
| **Concurrency** | Row locking (`select_for_update`) on balance/state mutations | `MUST` | Add `select_for_update()` inside `transaction.atomic()` |
| **Reliability** | Tasks enqueued with `transaction.on_commit()` | `MUST` | Wrap Celery `.delay()` calls in `on_commit` |
| **Error Handling** | Typed domain exceptions caught globally by `@api.exception_handler` | `MUST` | Raise custom exceptions; remove view `try/except` |
| **Documentation** | Explicit `Path(...)`, `Query(...)` parameter annotations | `SHOULD` | Annotate all operation parameters explicitly |
