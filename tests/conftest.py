"""Shared pytest fixtures for all tests."""

import pytest
from fastapi.testclient import TestClient

from main import app
from services.storage import connection_store, policy_store


@pytest.fixture(autouse=True)
def clear_stores():
    """Clear all stores before and after each test."""
    policy_store.clear()
    connection_store.clear()
    yield
    policy_store.clear()
    connection_store.clear()


@pytest.fixture
def test_client():
    """FastAPI test client."""
    return TestClient(app)

