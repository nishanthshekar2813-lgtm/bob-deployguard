# System Architecture & Enterprise Compliance Specification
**Project:** User Vault & Identity Service (`user-vault-service`)  
**Document Revision:** 2.4.0-RELEASE  
**Engine Compliance Target:** IBM Bob 2.0 Autonomous Verification Engine (AST & Semantic Linter)  
**Classification:** Internal Developer Standard / Automated CI Gate Source of Truth  

---

## 1. Overview & Purpose

This document serves as the **immutable source of truth** for both human engineers and automated compliance subagents—specifically **IBM Bob 2.0 Document Understanding Subagent A**. 

Every Pull Request submitted to this repository is parsed against the architectural rules defined herein. Any AST (Abstract Syntax Tree) deviation, contract violation, or bypass of the security patterns below will immediately block release promotion and trigger automated remediation.

---

## 2. Core Architectural Principles

```
+-------------------------------------------------------------------------+
|                           Incoming HTTP Request                         |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  Global Edge & Auth Middleware Layer                    |
|  - Rate Limiting                                                        |
|  - JWT Bearer Validation (/api/v2/* mandatory)                          |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                      Async Controller Layer                             |
|  - Request Body / Query DTO Validation                                  |
|  - Async Route Wrapping & Error Delegation                              |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                     Data Access Layer (Repository)                      |
|  - STRICT Parameterized SQL Binding ONLY ($1, $2, ...)                  |
|  - Zero String Interpolation or Concatenation Allowed                   |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                 Global Error Handling Middleware Layer                  |
|  - Sanitized RFC-7807 JSON Error Responses                              |
|  - Redaction of Internal Stack Traces in Non-Local Environments         |
+-------------------------------------------------------------------------+
```

---

## 3. Strict Compliance Guidelines

### Guideline 1: Security & Data Validation (SQL Injection Zero-Tolerance)
> **Rule ID:** `SEC-RULE-001`  
> **Severity:** CRITICAL / BLOCKER (CVSS 9.8)  
> **AST Validator:** `Bob.Security.TaintAnalyzer`

All database queries executed against application databases (PostgreSQL, MariaDB, CockroachDB, etc.) **must strictly use parameterized inputs or prepared statement bindings**.

1. **Prohibited Patterns:**
   - String concatenation using `+` operator inside query strings.
   - Template literals (ES6 backtick interpolation `${var}`) inside raw SQL queries.
   - Passing unescaped ORM raw clauses (e.g., `sequelize.literal()`, `knex.raw()`) constructed with user-controlled input (`req.query`, `req.body`, `req.params`, `req.headers`).

2. **Mandatory Standard:**
   - Parameter placeholders (`$1`, `$2` for PostgreSQL or `?` for MySQL/SQLite) must be passed with a discrete parameters array.
   - Typed schema query builders (Drizzle, Prisma, or parameterized Knex bindings) are approved, provided dynamic clauses utilize parameterized parameters.

#### Non-Compliant Pattern (Will be flagged by Bob 2.0 Subagent B):
```typescript
// VIOLATION: Raw string concatenation introduces CWE-89 SQL Injection
export async function getUserById(req: Request, res: Response) {
  const user = await db.query(
    "SELECT * FROM users WHERE id = '" + req.query.id + "'"
  );
  return res.status(200).json(user);
}
```

#### Compliant Pattern:
```typescript
// COMPLIANT: Parameterized query binding
export async function getUserById(req: Request, res: Response) {
  const userId = String(req.query.id);
  const result = await db.query(
    "SELECT id, username, email, created_at FROM users WHERE id = $1",
    [userId]
  );
  if (result.rows.length === 0) {
    return res.status(404).json({ error: "User not found" });
  }
  return res.status(200).json(result.rows[0]);
}
```

---

### Guideline 2: Authentication & Authorization Enforcing
> **Rule ID:** `AUTH-RULE-002`  
> **Severity:** HIGH / RELEASE GATE  
> **AST Validator:** `Bob.Auth.RouteContractGate`

All REST API endpoints structured under the `/api/v2/` hierarchy must enforce cryptographic JWT token verification via the HTTP `Authorization` request header.

1. **Mandatory Token Header Format:**
   ```http
   Authorization: Bearer <JWT_ENCODED_TOKEN>
   ```

2. **Middleware Binding:**
   - Every route registered under `/api/v2/*` must mount the `verifyJwtToken` middleware before any controller execution.
   - Public exceptions (e.g., `/api/v2/auth/login`, `/api/v2/auth/register`, `/api/v2/healthz`) must be explicitly whitelisted in the `PUBLIC_ROUTE_EXEMPTIONS` registry with formal security sign-off.
   - The token verification step must cryptographically validate signature (`RS256` or `EdDSA`), verify expiration (`exp`), issuer (`iss`), and audience (`aud`).
   - Validated claims must populate `req.user` with tenant context (`tenant_id`, `user_id`, `roles`).

#### Compliant Route Registration Example:
```typescript
import { Router } from "express";
import { verifyJwtToken } from "@/middleware/auth.middleware";
import { getUserProfile, updateUserProfile } from "@/controllers/v2/users";

const v2Router = Router();

// Enforce JWT validation on entire v2 sub-router or route definition
v2Router.use(verifyJwtToken);

v2Router.get("/users/me", getUserProfile);
v2Router.patch("/users/me", updateUserProfile);

export default v2Router;
```

---

### Guideline 3: API Deprecation & Backward Compatibility Policy
> **Rule ID:** `API-RULE-003`  
> **Severity:** HIGH / BREAKING CONTRACT GATE  
> **AST Validator:** `Bob.DocumentUnderstanding.InterfaceDriftAuditor`

Deprecating legacy endpoints (including `/api/v1/*` routes) without an active backward-compatibility fallback wrapper is **strictly prohibited**.

1. **Zero-Downtime Migration Policy:**
   - Any deprecation notice requires a minimum 180-day grace period.
   - Deprecated `/api/v1/` endpoints must not be deleted or replaced with breaking signatures.
   - Deprecated v1 endpoints must wrap and transform requests internally into the canonical v2 controller format, returning backward-compatible JSON response structures.
   - The response must emit standardized deprecation HTTP headers:
     ```http
     Deprecation: @1735689600
     Sunset: Wed, 30 Jun 2027 00:00:00 GMT
     Link: </api/v2/users>; rel="successor-version"
     ```

#### Compliant Fallback Adapter Pattern:
```typescript
// COMPLIANT: v1 route preserved as fallback adapter mapping to modern logic
v1Router.get("/user", async (req, res, next) => {
  res.setHeader("Deprecation", "true");
  res.setHeader("Sunset", "2027-06-30T00:00:00Z");
  res.setHeader("Link", '</api/v2/users>; rel="successor-version"');

  try {
    // Adapter transforms legacy query shape to v2 service payload
    const v2Result = await userService.getUserById(req.query.legacy_uid);
    // Preserves old v1 contract fields for client backwards-compatibility
    return res.status(200).json({
      status: "success",
      data: {
        userId: v2Result.id,
        fullName: v2Result.username,
        emailAddress: v2Result.email
      }
    });
  } catch (err) {
    next(err);
  }
});
```

---

### Guideline 4: Error Handling & Stack Trace Redaction
> **Rule ID:** `ERR-RULE-004`  
> **Severity:** HIGH / OWASP A04/A05 ENFORCEMENT  
> **AST Validator:** `Bob.Architecture.ExceptionBoundaryAuditor`

Unhandled exceptions in synchronous or asynchronous controllers must be intercepted by unified global error handling middleware without leaking internal stack traces or database schema metadata.

1. **Async Controller Encapsulation:**
   - All asynchronous controller functions must be wrapped with an `asyncHandler` or use an Express 5+ native promise boundary.
   - Bare `try/catch` blocks that swallow errors or emit arbitrary ad-hoc error formats are prohibited.
   - Caught exceptions must be passed to the next error middleware via `next(err)`.

2. **Global Sanitization Middleware:**
   - In production and staging environments, error responses must adhere to RFC 7807 (`application/problem+json`).
   - The fields `stack`, `sql`, `fileName`, and `internalCode` must be stripped from HTTP response payloads.
   - Diagnostic identifiers (e.g., `traceId`, `correlationId`) must be returned to the client to permit secure log triage.

#### Compliant Global Error Handler Example:
```typescript
import { Request, Response, NextFunction } from "express";

interface ApplicationError extends Error {
  statusCode?: number;
  code?: string;
}

export function globalErrorHandler(
  err: ApplicationError,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const statusCode = err.statusCode || 500;
  const traceId = req.headers["x-request-id"] || crypto.randomUUID();

  // Log full stack trace internally to telemetry (never to client)
  logger.error("Controller failure", {
    traceId,
    path: req.originalUrl,
    method: req.method,
    stack: err.stack,
  });

  // Client-safe response: Never expose internal callstack
  return res.status(statusCode).json({
    type: "https://errors.uservault.internal/" + (err.code || "INTERNAL_ERROR"),
    title: statusCode === 500 ? "Internal Server Error" : err.message,
    status: statusCode,
    traceId,
    timestamp: new Date().toISOString()
  });
}
```

---

## 4. Subagent Audit Matrix (IBM Bob 2.0 Integration)

| Subagent | Role | Evaluation Metric | Pass Condition |
| :--- | :--- | :--- | :--- |
| **Subagent A** | Document Understanding | Verification against `ARCHITECTURE.md` | 100% compliance with Rules `SEC-RULE-001` through `ERR-RULE-004` |
| **Subagent B** | Security & Auto-Fix | Static AST Taint Analysis | 0 Critical/High CVEs; AST Parameterization auto-applied |
| **Subagent C** | Release Notes & CHANGELOG | Semantic Git Diff Analyzer | Conventional Commits parsed into SemVer bump and `CHANGELOG.md` |

---

## 5. Verification Sign-off & Audit Log

- **Author:** Architecture Review Board (ARB) & AppSec Working Group  
- **Automated Enforcer:** IBM Bob 2.0 Engine  
- **Cryptographic Hash:** `sha256:d84f885e353ce5c7965421b44d21aa6a92911b3e8e78b7b2586df11fb50c763a`  
- **Enforcement Action:** PR failing these rules will be rejected by `Bob-DeployGuard` prior to branch merge.
