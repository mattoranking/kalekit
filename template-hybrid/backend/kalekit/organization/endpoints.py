from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import (
    OrgActor,
    get_current_user,
    require_org_member,
    require_org_permission,
)
from kalekit.auth.roles import role_has_permission
from kalekit.config import settings
from kalekit.models.organization import Organization
from kalekit.models.user import User
from kalekit.organization.repository import (
    LastOwnerError,
    NotPermittedError,
    add_member,
    change_member_role,
    create_invitation,
    get_member,
    get_valid_invitation_by_token_hash,
    list_members,
    mark_invitation_accepted,
    remove_member,
)
from kalekit.organization.schemas import (
    AcceptInvitationRequest,
    ChangeMemberRoleRequest,
    InvitationAckResponse,
    InviteMemberRequest,
    MemberListResponse,
    MemberResponse,
    OrganizationListResponse,
    OrganizationMembershipResponse,
)
from kalekit.organization.service import (
    generate_invitation_token,
    hash_invitation_token,
    invitation_token_expiry,
)
from kalekit.postgres import get_db_session
from kalekit.redis import get_redis
from kalekit.utils.email import get_email_sender, send_invitation_email
from kalekit.utils.rate_limit import check_and_increment

# Not scoped to a single organization_id -- this lists the caller's own
# memberships, so it lives at /organizations rather than
# /organizations/{organization_id}.
list_router = APIRouter(prefix="/organizations", tags=["organizations"])

router = APIRouter(prefix="/organizations/{organization_id}", tags=["organizations"])

# Deliberately not nested under /organizations/{organization_id}: which
# org the invitation belongs to is a property of the token, not
# something the accepting user is trusted to assert via the URL.
invitation_router = APIRouter(prefix="/invitations", tags=["organizations"])


@list_router.get("", response_model=OrganizationListResponse)
async def list_my_organizations(
    user: Annotated[User, Depends(get_current_user)],
) -> OrganizationListResponse:
    """The organizations the caller belongs to, plus their role in each.

    UX only -- for deciding what to show (e.g. "delete", "invite",
    settings controls), not authorization. The API remains the
    authority via `require_org_permission`.
    """
    return OrganizationListResponse(
        items=[
            OrganizationMembershipResponse(
                id=m.organization.id, name=m.organization.name, role=m.role
            )
            for m in user.memberships
        ]
    )


@router.get("/members", response_model=MemberListResponse)
async def get_members(
    organization_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _caller: Annotated[User, Depends(require_org_member)],
) -> MemberListResponse:
    """Any role can see the roster — this is a read, not a change."""
    rows = await list_members(session, organization_id=organization_id)
    return MemberListResponse(
        items=[
            MemberResponse(user_id=uid, email=email, role=role)
            for uid, email, role in rows
        ]
    )


@router.patch("/members/{user_id}", response_model=MemberResponse)
async def change_organization_member_role(
    organization_id: UUID,
    user_id: UUID,
    body: ChangeMemberRoleRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    caller: Annotated[OrgActor, Depends(require_org_permission("members:manage"))],
) -> MemberResponse:
    """Changes `user_id`'s role within the organization.

    Governed by the same "cannot act on or grant a role above your
    own" rule as inviting (#29): the caller must be able to grant the
    *new* role (`members:grant:<new role>`) -- an admin can never
    produce an owner -- and must also be able to grant the member's
    *current* role, which is what stands in for "can this caller act
    on someone at this role at all" (only an owner holds
    `members:grant:owner`, so only an owner can touch another owner,
    including demoting them).

    That authorization check is done *inside* `change_member_role`,
    against the target's role as re-read under the organization row's
    lock -- not against an earlier, unlocked fetch here. Checking here
    instead would open a real privilege-escalation race: the caller
    could be authorized against a target who was e.g. `member` at
    check time, then have a concurrent request promote that same
    target to `owner` before this request's mutation actually runs,
    letting an admin who was never authorized to touch an owner act on
    one anyway. See `change_member_role`'s and `NotPermittedError`'s
    docstrings.

    Refuses (409) any change that would leave the organization with
    zero owners -- including an owner demoting themselves. See
    `change_member_role`'s docstring for the concurrency-safe
    last-owner check.
    """
    try:
        member = await change_member_role(
            session,
            organization_id=organization_id,
            user_id=user_id,
            role=body.role,
            caller_role=caller.role,
        )
    except NotPermittedError:
        raise HTTPException(
            status_code=403,
            detail="Cannot act on or grant a role above your own",
        )
    except LastOwnerError:
        raise HTTPException(
            status_code=409,
            detail="Cannot demote the organization's last owner",
        )
    if member is None:
        raise HTTPException(status_code=404, detail="Not found")

    # Fetched directly rather than via `member.user` -- that relationship
    # is lazy-loaded and would require an extra awaited refresh in an
    # async context; a direct `session.get` is simpler here.
    target_user = await session.get(User, user_id)
    return MemberResponse(
        user_id=member.user_id,
        email=target_user.email if target_user else None,
        role=member.role,
    )


@router.delete("/members/{user_id}", status_code=204)
async def remove_organization_member(
    organization_id: UUID,
    user_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    caller: Annotated[OrgActor, Depends(require_org_permission("members:manage"))],
) -> None:
    """Removes `user_id` from the organization.

    Same "cannot act on a role above your own" rule as role changes
    above: only an owner can remove another owner. An admin/owner
    removing *themselves* via this route works the same as removing
    anyone else -- they're gated on `members:manage`, which they've
    already satisfied, and (being an owner or admin) always passes the
    act-on check against their own current role.

    That check runs inside `remove_member`, against the target's role
    re-read under the organization row's lock rather than an earlier
    unlocked fetch here -- see `change_organization_member_role`'s
    docstring for why an unlocked pre-check is a real
    privilege-escalation race, not just a theoretical concern.

    Refuses (409) to remove the organization's last owner -- an org
    must never reach zero owners through this API. 404 if `user_id`
    isn't currently a member.
    """
    try:
        member = await remove_member(
            session,
            organization_id=organization_id,
            user_id=user_id,
            caller_role=caller.role,
        )
    except NotPermittedError:
        raise HTTPException(
            status_code=403,
            detail="Cannot act on a member with a role above your own",
        )
    except LastOwnerError:
        raise HTTPException(
            status_code=409,
            detail="Cannot remove the organization's last owner",
        )
    if member is None:
        raise HTTPException(status_code=404, detail="Not found")


@router.post("/leave", status_code=204)
async def leave_organization(
    organization_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(require_org_member)],
) -> None:
    """Removes the caller from the organization. Open to any role --
    unlike removing *someone else*, leaving yourself needs no
    `members:manage` permission check, and there's no "act on a role
    above your own" question to ask since you're only ever acting on
    your own membership.

    Still subject to the last-owner protection: the organization's
    sole remaining owner cannot leave (they'd need to promote another
    owner first, or transfer ownership -- see #16/#30's deferred
    ownership-transfer flow).
    """
    try:
        member = await remove_member(
            session, organization_id=organization_id, user_id=user.id
        )
    except LastOwnerError:
        raise HTTPException(
            status_code=409,
            detail="Cannot leave: you are the organization's last owner",
        )
    if member is None:
        # Unreachable in practice: require_org_member already confirmed
        # the caller is a member of this organization_id.
        raise HTTPException(status_code=404, detail="Not found")


@router.post("/invitations", response_model=InvitationAckResponse, status_code=202)
async def create_organization_invitation(
    organization_id: UUID,
    body: InviteMemberRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    caller: Annotated[OrgActor, Depends(require_org_permission("members:invite"))],
    background_tasks: BackgroundTasks,
) -> InvitationAckResponse:
    """Invites `body.email` to join the organization at `body.role`.

    Only admin/owner can invite — and only at a role they're permitted
    to grant (see `members:grant:<role>` in `auth/roles.py::ROLE_PERMISSIONS`).
    Only an owner can grant the owner role — an admin can invite
    admin/member/viewer, never owner. That grant check is repeated
    against the inviter's *current* role at accept time too (see
    `accept_invitation`), since it may no longer hold by then.

    Always returns the same 202 body, whether or not `email` belongs to
    a registered user and whether or not they're already a member --
    this endpoint never looks that up, so it has nothing to leak
    (issue #24/#31). No membership is created here; that only happens
    when the invitee accepts while authenticated as the matching email,
    via `POST /invitations/accept`.
    """
    if not role_has_permission(caller.role, f"members:grant:{body.role.value}"):
        raise HTTPException(
            status_code=403,
            detail="Cannot grant a role higher than your own",
        )

    # Called here, synchronously, purely to surface a misconfigured
    # deployment as a request-time failure -- `get_email_sender` raises
    # outside dev/test when no real provider is wired up. Left to raise
    # only from inside the `BackgroundTasks` callback below (which runs
    # after this response has already been sent), the caller would see
    # a normal 202 "invitation sent" while the email silently never
    # goes out, which defeats the whole point of that function failing
    # loudly. `send_invitation_email` still calls it again itself when
    # the background task actually runs; that's harmless and not worth
    # a shared-instance refactor to avoid.
    get_email_sender()

    organization = await session.get(Organization, organization_id)
    if organization is None:
        # Unreachable in practice: require_org_permission already
        # confirmed the caller has a membership row pointing at this
        # organization_id.
        raise HTTPException(status_code=404, detail="Not found")

    r = await get_redis()
    # Check/increment the org-wide limit first, and only touch the
    # inviter's personal counter if that passes. An org already at its
    # limit shouldn't also burn quota from an inviter who did nothing
    # wrong -- the reverse (an inviter-exceeded request still costing
    # the org a unit) is fine to leave as-is, since it's still a real
    # attempted invite against that org's overall throughput.
    org_allowed = await check_and_increment(
        r,
        f"invitation_rate:org:{organization_id}",
        limit=settings.INVITATION_RATE_LIMIT_PER_ORG,
        window_seconds=settings.INVITATION_RATE_LIMIT_WINDOW_SECONDS,
    )
    if not org_allowed:
        raise HTTPException(
            status_code=429, detail="Too many invitations, try again later"
        )
    inviter_allowed = await check_and_increment(
        r,
        f"invitation_rate:user:{caller.user.id}",
        limit=settings.INVITATION_RATE_LIMIT_PER_INVITER,
        window_seconds=settings.INVITATION_RATE_LIMIT_WINDOW_SECONDS,
    )
    if not inviter_allowed:
        raise HTTPException(
            status_code=429, detail="Too many invitations, try again later"
        )

    email = body.email.lower()
    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=organization_id,
        email=email,
        role=body.role,
        token_hash=hash_invitation_token(raw_token),
        invited_by=caller.user.id,
        expires_at=invitation_token_expiry(),
    )
    # Deferred via BackgroundTasks (runs after the response is sent,
    # which is after `get_db_session`'s post-return commit has already
    # completed) rather than awaited here -- awaiting it inline would
    # let the invitee receive a working-looking link before the token
    # row is durably committed, so a crash or unrelated commit failure
    # between the email going out and the commit completing would leave
    # a silently dead invitation.
    background_tasks.add_task(
        send_invitation_email,
        to=email,
        organization_name=organization.name,
        token=raw_token,
        role=body.role,
    )
    return InvitationAckResponse()


@invitation_router.post("/accept", response_model=MemberResponse, status_code=201)
async def accept_invitation(
    body: AcceptInvitationRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> MemberResponse | JSONResponse:
    """Creates the membership the invitation names -- only for the
    authenticated user whose own email matches it. The invitee's email
    is never trusted from the request body, only from `user`, so
    accepting someone else's invitation link never adds you (or them)
    to an org neither of you should be in.

    The role granted is re-checked against `invited_by`'s *current*
    role in the org, not just whatever it was when the invitation was
    created -- an admin who has since been demoted (or removed
    entirely) cannot have an outstanding invitation retroactively grant
    a role they could no longer grant themselves (issue #31). A
    since-demoted inviter's pending invitations are simply refused,
    not silently downgraded to whatever the inviter can grant now --
    the invitee asked for (and was promised) a specific role, and
    granting a different one without their knowledge would be its own
    kind of surprise.
    """
    invitation = await get_valid_invitation_by_token_hash(
        session, hash_invitation_token(body.token)
    )
    if invitation is None:
        raise HTTPException(status_code=400, detail="Invalid or expired invitation")

    if user.email is None or user.email.lower() != invitation.email:
        raise HTTPException(
            status_code=403, detail="This invitation is for a different email address"
        )

    inviter_membership = (
        await get_member(
            session,
            organization_id=invitation.organization_id,
            user_id=invitation.invited_by,
        )
        if invitation.invited_by is not None
        else None
    )
    if inviter_membership is None or not role_has_permission(
        inviter_membership.role, f"members:grant:{invitation.role.value}"
    ):
        # The inviter is gone, or has been demoted since sending this
        # invitation, and can no longer grant the offered role. Left
        # unconsumed (not marked accepted) rather than burned -- if the
        # inviter is later restored to a sufficient role, the same
        # invitation can still be honored instead of forcing a resend.
        raise HTTPException(
            status_code=403,
            detail="This invitation can no longer be granted",
        )

    member, created = await add_member(
        session,
        organization_id=invitation.organization_id,
        user_id=user.id,
        role=invitation.role,
    )
    # Single-use regardless of the outcome below -- either way, this
    # token has now been consumed.
    await mark_invitation_accepted(session, invitation)

    if not created:
        # Already a member (e.g. joined some other way, or lost a race
        # against a concurrent accept of this same token) -- `add_member`
        # itself is idempotent, but the invitation's single-use guarantee
        # means only one accept of a given token should ever look like
        # "this just made you a member".
        #
        # Returned (not raised) deliberately: `get_db_session` commits on
        # a normal return and rolls back on any exception propagating out
        # of the endpoint. An `HTTPException` here would roll back the
        # `mark_invitation_accepted` flush above along with it, leaving
        # `accepted_at` NULL -- the token would silently still be valid
        # and replayable despite the 409, contradicting the single-use
        # guarantee this whole endpoint exists to enforce. Returning a
        # `Response` subclass directly bypasses `response_model`
        # validation, so the 409 body is constructed by hand instead of
        # via `MemberResponse`.
        return JSONResponse(status_code=409, content={"detail": "Already a member"})

    return MemberResponse(user_id=user.id, email=user.email, role=member.role)
