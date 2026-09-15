import pytest
from httpx import AsyncClient


@pytest.mark.asyncio(loop_scope="session")
async def test_health_endpoint(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
