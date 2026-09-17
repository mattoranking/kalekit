# Kalekit Auth Hardening — Product Update

Running log of coordinated engineering progress on the kalekit auth-hardening
backlog, maintained by Scofield (coordinator) across the RBAC, ABAC, and
Hybrid template streams. Newest entry first.

---

## 2026-09-17 14:56 UTC

**39 issues merged to main** (up from 31 at the last entry). This stretch
found and closed a significant, previously-invisible gap, then used it to
drive the next wave of work.

### The discovery: ABAC and Hybrid were still running pre-hardening auth code

Ten issues (#3, #4, #5, #6, #7, #9, #10, #11, #14, #15) showed as **closed**
on the tracker, but a direct check of `template-abac/backend`'s code showed
its `/auth/refresh` endpoint still decoding a JWT refresh token via the
deprecated `python-jose` library and trusting it on signature alone — never
checked against the database, and a refresh still revoked every session on
every device. The same was true of Hybrid. These issues use one shared
GitHub issue number across all three template trees, so the issue closed
the moment RBAC got the fix — ABAC and Hybrid never actually got it. This
was a real, currently-exploitable gap in two of three templates, not a
process error in any individual PR (each one was correctly scoped to the
single template it was asked to touch).

Filed **#85** (ABAC) and **#86** (Hybrid) to port RBAC's already-shipped
DB-validated, rotating-refresh-token pattern into both templates. Both
merged (PRs #87, #90) — opaque SHA-256-hashed tokens, per-family rotation
with reuse detection, a Redis-backed grace window for legitimate concurrent
refreshes, `python-jose` → `PyJWT`, and the OAuth callback's missing
persistence step, all ported without touching either template's
organization/role layer.

Along the way, both ports surfaced concurrency bugs **inherited from RBAC's
own already-shipped, already-multiply-reviewed reference implementation**
— not introduced by the ports:
- No row lock on refresh-token rotation, letting two truly-concurrent
  requests both rotate the same token (filed as **#91** to backport to
  RBAC; fixed directly in both ports).
- The refresh grace-window cache had no resilience to Redis errors or
  corrupted cached values, both capable of turning a successful refresh
  into an unhandled 500 (filed as **#92** to backport to RBAC; fixed
  directly in both ports).
- A subtler one specific to combining the two fixes above: deferring the
  grace-cache write to run after the response (the correct pattern
  elsewhere in this codebase, e.g. invitation emails) turned out to be
  *wrong* here specifically, because the row lock's release is tied to the
  database commit, which now happens *before* a deferred write — a second,
  legitimately concurrent request could unblock and find the cache still
  empty, incorrectly failing closed instead of getting the shared pair.
  Caught by Copilot at round 4 on the Hybrid port, independently verified,
  fixed by keeping that one write inline instead of deferred. Documented on
  #91 so the eventual RBAC port doesn't reintroduce it.

### Also shipped this stretch

- **#18** (RBAC rate limiting) — per-IP/per-account/per-session/per-user
  fixed-window limits on login, register, refresh, and resend-verification,
  with a `Retry-After` header and a TTL-recovery fix ported from ABAC's
  invitation rate limiter.
- **#17** (RBAC password reset) — reuses the existing email-verification-
  token pattern, but redemption uses a single atomic `UPDATE ... WHERE
  used_at IS NULL ... RETURNING` rather than the check-then-mark pattern
  used elsewhere, specifically because this token authorizes a full
  password change plus session wipe and the stakes justified the stronger
  primitive. A successful reset revokes every session. The reset-request
  endpoint defers its email send to run after the response, closing a
  timing-based enumeration oracle Copilot caught at round 1.
- Issue #16 (step-up re-authentication) is in progress at the time of this
  entry.

### Process change: subagents now own their own Copilot review rounds

Previously every Copilot finding, however trivial, was relayed through the
coordinator. That's now split: **implementing subagents handle Copilot
rounds 1-2 themselves** (request, poll, judge against a documented
false-positive playbook, fix, re-request), escalating to the coordinator at
round 3 or immediately if a finding touches security/concurrency or might
be a false positive not yet catalogued. The coordinator still reads every
diff independently and immediately regardless of round — that's where
several of the bugs above were actually caught, not from reacting to
automated review output. This cut a meaningful amount of relay overhead:
most PRs in this stretch resolved within 1-2 self-served rounds.

The `copilot-pr-review` skill now carries a running "known false-positive
patterns" list (the recurring "needs a migration" complaint on a project
that deliberately ships none; a mapper-configuration false alarm) so that
knowledge doesn't have to be relearned by each fresh subagent.

### Known open gaps (not yet actioned)

- The genuinely-open, cross-cutting backlog items (#12 provider-token
  encryption, #13 BFF/httpOnly cookies, #19 native mobile OAuth, #20 audit
  log, #22 platform-admin design) still need a scoping decision — each
  touches multiple templates and none has a clean single-template slice
  identified yet, unlike #16/#17/#18's RBAC-first treatment.
- #79 (RBAC `invalidate_role_cache` has no call site yet) remains a tracked
  debt marker, not actionable until an admin role-editing endpoint exists.
- ABAC's #24 org-lockout-after-creator-leaves edge case (noted in the last
  entry) is still not filed as its own tracked issue.
- #91 and #92 (RBAC backports of the row-lock and Redis-resilience fixes)
  are filed but not yet dispatched.

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
