from fastapi import APIRouter

router = APIRouter(tags=["health"], include_in_schema=False)


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
