# Kalekit Auth Hardening — Product Update

Running log of coordinated engineering progress on the kalekit auth-hardening
backlog, maintained by Scofield (coordinator) across the RBAC, ABAC, and
Hybrid template streams. Newest entry first.

---

## 2026-09-17 11:38 UTC

**31 issues merged to main.** All three templates (RBAC, ABAC, Hybrid) have
had their core auth-hardening backlog worked through in parallel across four
coordination streams, each PR gated by an independent Copilot review pass
plus a manual diff review before merge.

### What shipped this session

**RBAC** — client-bound tokens (web/mobile/admin, via JWT `aud`), per-client
access-token and session lifetimes, sliding idle expiration + an absolute
session cutoff for admin sessions, live permission resolution (a revoked
role/permission now applies within ~60s instead of only on token refresh),
and a swept-up dead-code removal (#61). Two pre-existing, unrelated bugs
found and fixed along the way: a missing `verify_password` import that would
500 on first use, and a stale `python-jose` import breaking the whole test
suite's collection.

**ABAC** — replaced a direct, enumeration-prone "add member by email"
endpoint with a consent-based invitation flow (hashed single-use expiring
tokens, a pluggable email sender that fails loudly outside dev/test rather
than silently logging secrets, per-org/per-inviter rate limiting), plus the
non-delete slice of organization lifecycle (create additional orgs, rename,
remove member, leave — deletion itself deferred pending step-up
re-authentication, issue #16, not yet built), and a null-safety fix for
member listing when a member's email is null (OAuth providers like
Twitter/X that don't expose one).

**Hybrid** — currently in flight: porting ABAC's invitation-flow pattern
(issue #31), adapted for Hybrid's per-membership role model (an invitation
now carries the role being offered, gated by the `members:grant:<role>`
permission rather than ABAC's simpler creator-only policy).

### Process notes

- Every PR went through: Copilot review requested → wait for the actual
  posted review (not the pending-request state) → check for human PR
  comments → my own diff review → real findings routed back to the
  implementing stream, trivial zero-risk wording/import fixes applied
  directly → capped at 5 review rounds before escalating to the user for a
  judgment call.
- One review cycle (PR #74, issue #24) and one other (PR #75, issue #6)
  both hit the 5-round cap; both were escalated and resolved with explicit
  user sign-off rather than pushed through unilaterally.
- Filed **#79** as a tracking issue for a debt left behind by #6: the
  Redis role-permission cache's `invalidate_role_cache` has no call site
  yet (nothing in RBAC dynamically edits role permissions today), so the
  60s cache TTL is currently the only thing keeping permission-revocation
  latency low. Whoever eventually builds a role-editing admin endpoint
  needs to call it.

### Known open gaps (not yet actioned)

- Issue #16 (step-up re-authentication for sensitive actions) is unblocked
  work with no owner yet — it's a dependency for ABAC's org-deletion
  endpoint (#25, partially shipped) and Hybrid's ownership-transfer work
  (#30).
- Issue #73 (RBAC: `list_user_sessions` loads all refresh-token rows
  including revoked/expired ones — unbounded growth) is filed, not yet
  dispatched.
- ABAC issue #24's invitation flow permanently locks an org out of inviting
  new members if its creator leaves or is removed (`require_org_creator`
  has no fallback once `created_by` is null) — flagged during #25's review,
  not yet filed as its own tracked issue.

---
