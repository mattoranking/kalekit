from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import (
    get_current_user,
    require_org_admin,
    require_org_creator,
    require_org_member,
)
from kalekit.config import settings
from kalekit.models.organization import Organization
from kalekit.models.user import User
from kalekit.organization.repository import (
    LastMemberError,
    add_member,
    create_invitation,
    create_organization,
    get_valid_invitation_by_token_hash,
    list_members,
    list_user_organizations,
    mark_invitation_accepted,
    remove_member,
    rename_organization,
)
from kalekit.organization.schemas import (
    AcceptInvitationRequest,
    InvitationAckResponse,
    InviteMemberRequest,
    MemberListResponse,
    MemberResponse,
    OrganizationCreateRequest,
    OrganizationListResponse,
    OrganizationRenameRequest,
    OrganizationResponse,
)
from kalekit.organization.service import (
    generate_invitation_token,
    hash_invitation_token,
    invitation_token_expiry,
)
from kalekit.postgres import get_db_session
from kalekit.redis import get_redis
from kalekit.utils.email import send_invitation_email
from kalekit.utils.rate_limit import check_and_increment

router = APIRouter(prefix="/organizations", tags=["organizations"])
member_router = APIRouter(
    prefix="/organizations/{organization_id}", tags=["organizations"]
)
# Deliberately not nested under /organizations/{organization_id}: which
# org the invitation belongs to is a property of the token, not
# something the accepting user is trusted to assert via the URL.
invitation_router = APIRouter(prefix="/invitations", tags=["organizations"])


@router.get("", response_model=OrganizationListResponse)
async def get_my_organizations(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> OrganizationListResponse:
    """Lists the organizations the caller is a member of."""
    organizations = await list_user_organizations(session, user_id=user.id)
    return OrganizationListResponse(
        items=[OrganizationResponse.model_validate(org) for org in organizations]
    )


@router.post("", response_model=OrganizationResponse, status_code=201)
async def create_new_organization(
    body: OrganizationCreateRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> OrganizationResponse:
    """Creates an additional organization for the caller. Unlike the
    organization created at signup, this is opt-in: any authenticated
    user may create more organizations, becoming both the creator and
    first (and, until they invite someone, only) member of each one.
    """
    organization = await create_organization(
        session, name=body.name, created_by=user.id
    )
    await add_member(session, organization_id=organization.id, user_id=user.id)
    return OrganizationResponse.model_validate(organization)


@member_router.patch("", response_model=OrganizationResponse)
async def rename_org(
    organization_id: UUID,
    body: OrganizationRenameRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    organization: Annotated[Organization, Depends(require_org_admin)],
) -> OrganizationResponse:
    """Renames the organization. Gated by `require_org_admin`: the
    org's creator, or any member if it has none (see that dependency's
    docstring) -- 404 to non-members, 403 to a member who isn't the
    creator of an org that still has one.
    """
    organization = await rename_organization(
        session, organization=organization, name=body.name
    )
    return OrganizationResponse.model_validate(organization)


@member_router.delete("/members/{user_id}", status_code=204)
async def remove_organization_member(
    organization_id: UUID,
    user_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _organization: Annotated[Organization, Depends(require_org_admin)],
) -> None:
    """Removes a member from the organization. Same admin gate as
    renaming -- un-inviting someone is as consequential as growing the
    tenant, which #24 already restricted to the creator (or any member
    once the org has none, per `require_org_admin`).

    Refuses (409) to remove the organization's last member -- an org
    must never reach zero members through this API. 404 if `user_id`
    isn't currently a member (including the caller removing themselves
    via this route; they should use `POST .../leave` instead, which
    carries the same last-member protection).
    """
    try:
        member = await remove_member(
            session, organization_id=organization_id, user_id=user_id
        )
    except LastMemberError:
        raise HTTPException(
            status_code=409,
            detail="Cannot remove the last member of an organization",
        )
    if member is None:
        raise HTTPException(status_code=404, detail="Not found")


@member_router.post("/leave", status_code=204)
async def leave_organization(
    organization_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(require_org_member)],
) -> None:
    """Removes the caller from the organization. Open to any member --
    unlike removing *someone else*, leaving yourself needs no creator
    check -- but subject to the same last-member protection: the sole
    remaining member of an organization cannot leave it (they'd have to
    delete the organization instead, which is out of scope here pending
    #16's step-up re-auth).
    """
    try:
        member = await remove_member(
            session, organization_id=organization_id, user_id=user.id
        )
    except LastMemberError:
        raise HTTPException(
            status_code=409,
            detail="Cannot leave: you are the last member of this organization",
        )
    if member is None:
        # Unreachable in practice: require_org_member already confirmed
        # the caller is a member of this organization_id.
        raise HTTPException(status_code=404, detail="Not found")


@member_router.get("/members", response_model=MemberListResponse)
async def get_members(
    organization_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _caller: Annotated[User, Depends(require_org_member)],
) -> MemberListResponse:
    """Lists members of this organization only.

    A caller who isn't a member never reaches this line — `require_org_member`
    already turned that case into a 404 before the query ran.
    """
    rows = await list_members(session, organization_id=organization_id)
    return MemberListResponse(
        items=[MemberResponse(user_id=uid, email=email) for uid, email in rows]
    )


@member_router.post(
    "/invitations", response_model=InvitationAckResponse, status_code=202
)
async def create_organization_invitation(
    organization_id: UUID,
    body: InviteMemberRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    organization: Annotated[Organization, Depends(require_org_creator)],
    background_tasks: BackgroundTasks,
) -> InvitationAckResponse:
    """Invites `body.email` to join the organization.

    Always returns the same 202 body, whether or not `email` belongs to
    a registered user and whether or not they're already a member --
    this endpoint never looks that up, so it has nothing to leak
    (issue #24). No membership is created here; that only happens when
    the invitee accepts while authenticated as the matching email, via
    `POST /invitations/accept`.
    """
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
        f"invitation_rate:user:{organization.created_by}",
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
        token_hash=hash_invitation_token(raw_token),
        invited_by=organization.created_by,
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

    _member, created = await add_member(
        session, organization_id=invitation.organization_id, user_id=user.id
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

    return MemberResponse(user_id=user.id, email=user.email)
