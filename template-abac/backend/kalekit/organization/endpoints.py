from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import (
    get_current_user,
    require_org_creator,
    require_org_member,
)
from kalekit.config import settings
from kalekit.models.organization import Organization
from kalekit.models.user import User
from kalekit.organization.repository import (
    add_member,
    create_invitation,
    get_valid_invitation_by_token_hash,
    list_members,
    list_user_organizations,
    mark_invitation_accepted,
)
from kalekit.organization.schemas import (
    AcceptInvitationRequest,
    InvitationAckResponse,
    InviteMemberRequest,
    MemberListResponse,
    MemberResponse,
    OrganizationListResponse,
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
    org_allowed = await check_and_increment(
        r,
        f"invitation_rate:org:{organization_id}",
        limit=settings.INVITATION_RATE_LIMIT_PER_ORG,
        window_seconds=settings.INVITATION_RATE_LIMIT_WINDOW_SECONDS,
    )
    inviter_allowed = await check_and_increment(
        r,
        f"invitation_rate:user:{organization.created_by}",
        limit=settings.INVITATION_RATE_LIMIT_PER_INVITER,
        window_seconds=settings.INVITATION_RATE_LIMIT_WINDOW_SECONDS,
    )
    if not org_allowed or not inviter_allowed:
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
    await send_invitation_email(
        to=email, organization_name=organization.name, token=raw_token
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
