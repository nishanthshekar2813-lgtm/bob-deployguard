/**
 * @file server.js
 * @description Sample Node.js Express server with intentional security and architectural flaws
 * designed for automated detection and remediation by IBM Bob 2.0 Autonomous Agent.
 *
 * TARGET OF AUDIT:
 * 1. Hardcoded cryptographic credentials (CWE-798 / OWASP A07)
 * 2. Raw SQL string concatenation query injection (CWE-89 / OWASP A03)
 * 3. Sensitive administrative endpoint missing authorization middleware (CWE-306 / OWASP A01)
 * 4. Violation of ARCHITECTURE.md compliance rules (SEC-RULE-001, AUTH-RULE-002, ERR-RULE-004)
 */

const express = require("express");
const app = express();
const PORT = process.env.PORT || 4000;

// ============================================================================
// INTENTIONAL FLAW 1: Hardcoded secret string (CWE-798)
// Bob 2.0 Document Understanding & Secret Scanner Target
// ============================================================================
const JWT_SECRET = "super_secret_hardcoded_key_123";

// Mock Database Pool client simulating SQL execution
const db = {
  query: async (sqlString, params = []) => {
    console.log(`[DB DRIVER] Executing statement: ${sqlString}`);
    if (params.length > 0) {
      console.log(`[DB DRIVER] Bound parameters:`, params);
    }
    // Returns mock record set
    return {
      rows: [
        { id: 104, username: "alex_chen", email: "alex@enterprise.vault", role: "developer" }
      ]
    };
  }
};

app.use(express.json());

// Public healthcheck
app.get("/healthz", (req, res) => {
  res.status(200).json({ status: "healthy", service: "user-vault-service" });
});

// ============================================================================
// INTENTIONAL FLAW 2: Vulnerable SQL query using raw string concatenation (CWE-89)
// Subagent B (Security & Vulnerability Auto-Fix) Target
// Non-compliant with ARCHITECTURE.md Guideline 1 (SEC-RULE-001)
// ============================================================================
app.get("/api/users", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = '" + req.query.id + "'");
    res.json(result);
  } catch (err) {
    // Non-compliant error leaking stack to response
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ============================================================================
// INTENTIONAL FLAW 3: Missing authorization middleware on sensitive endpoint
// Non-compliant with ARCHITECTURE.md Guideline 2 (AUTH-RULE-002)
// Bob 2.0 Subagent A (Document Understanding) Audit Target
// ============================================================================

// TODO: Missing authorization middleware on this sensitive endpoint!
// Should require verifyJwtToken(JWT_SECRET) with admin claim check.
app.delete("/api/v2/users/:id", async (req, res) => {
  const targetId = req.params.id;
  // Administrative user purging executed without verifying Bearer JWT authorization header
  await db.query(`DELETE FROM users WHERE id = $1`, [targetId]);
  res.status(200).json({ success: true, message: `User ${targetId} purged from vault.` });
});

// Deprecated v1 endpoint without backward-compatibility fallback wrapper
// Violates ARCHITECTURE.md Guideline 3 (API-RULE-003)
app.get("/api/v1/user-legacy", (req, res) => {
  res.status(410).json({ message: "Endpoint discontinued. Migrate immediately." });
});

// Server listener
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[VULNERABLE SERVICE] Running on port ${PORT}`);
    console.log(`[BOB 2.0 ENGINE] Ready for PR #104 static AST taint analysis.`);
  });
}

module.exports = { app, JWT_SECRET };
