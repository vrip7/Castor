"""
Authentication endpoint tests.
"""

import pytest
from httpx import AsyncClient

from app.core.constants import UserStatus


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient, test_user_data: dict):
    """Test user registration."""
    response = await client.post(
        "/api/v1/auth/register",
        json=test_user_data,
    )
    
    assert response.status_code == 201
    data = response.json()
    assert "user_id" in data
    assert data["email"] == test_user_data["email"].lower()
    assert data["requires_verification"] is True


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient, test_user_data: dict):
    """Test registration with duplicate email."""
    # First registration
    await client.post("/api/v1/auth/register", json=test_user_data)
    
    # Second registration with same email
    response = await client.post("/api/v1/auth/register", json=test_user_data)
    
    assert response.status_code in [400, 422]


@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient):
    """Test login with invalid credentials."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "identifier": "nonexistent@example.com",
            "password": "wrongpassword",
        },
    )
    
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Test health check endpoint."""
    response = await client.get("/api/v1/health")
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_readiness_check(client: AsyncClient):
    """Test readiness check endpoint."""
    response = await client.get("/api/v1/health/ready")
    
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "checks" in data
