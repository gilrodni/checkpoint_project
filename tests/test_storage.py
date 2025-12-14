"""Unit tests for storage services."""

from datetime import datetime

import pytest

from models import Action, ConnectionDetail, Policy, Protocol
from services.storage import ConnectionStore, PolicyStore


def make_policy(policy_id: str, action: Action = Action.ALLOW) -> Policy:
    """Create a simple policy for testing."""
    return Policy(policy_id=policy_id, conditions=[], action=action)


def make_connection(connection_id: str, decision: Action = Action.ALLOW) -> ConnectionDetail:
    """Create a simple connection for testing."""
    return ConnectionDetail(
        connection_id=connection_id,
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        destination_port=443,
        protocol=Protocol.TCP,
        timestamp=datetime(2024, 1, 15, 10, 0, 0),
        decision=decision,
        anomaly_score=0.1,
    )


@pytest.fixture
def policy_store():
    return PolicyStore()


@pytest.fixture
def connection_store():
    return ConnectionStore()


class TestPolicyStore:
    """Tests for PolicyStore."""

    def test_add_and_get(self, policy_store):
        """Test adding and retrieving a policy."""
        policy_store.add(make_policy("test-1"))

        retrieved = policy_store.get("test-1")

        assert retrieved is not None
        assert retrieved.policy_id == "test-1"

    def test_get_nonexistent(self, policy_store):
        """Test getting a policy that doesn't exist."""
        assert policy_store.get("nonexistent") is None

    def test_get_all(self, policy_store):
        """Test retrieving all policies in order."""
        policy_store.add(make_policy("policy-1"))
        policy_store.add(make_policy("policy-2"))

        all_policies = policy_store.get_all()

        assert [p.policy_id for p in all_policies] == ["policy-1", "policy-2"]

    def test_delete_existing(self, policy_store):
        """Test deleting an existing policy."""
        policy_store.add(make_policy("to-delete"))

        assert policy_store.delete("to-delete") is True
        assert policy_store.get("to-delete") is None

    def test_delete_nonexistent(self, policy_store):
        """Test deleting a policy that doesn't exist."""
        assert policy_store.delete("nonexistent") is False

    def test_clear(self, policy_store):
        """Test clearing all policies."""
        policy_store.add(make_policy("p1"))
        policy_store.add(make_policy("p2"))

        policy_store.clear()

        assert policy_store.get_all() == []

    def test_update_replaces_existing(self, policy_store):
        """Test that adding a policy with same ID updates it."""
        policy_store.add(make_policy("same-id", Action.ALLOW))
        policy_store.add(make_policy("same-id", Action.BLOCK))

        retrieved = policy_store.get("same-id")

        assert retrieved.action == Action.BLOCK
        assert len(policy_store.get_all()) == 1


class TestConnectionStore:
    """Tests for ConnectionStore."""

    def test_add_and_get(self, connection_store):
        """Test adding and retrieving a connection."""
        connection_store.add(make_connection("conn-1"))

        retrieved = connection_store.get("conn-1")

        assert retrieved is not None
        assert retrieved.connection_id == "conn-1"

    def test_get_nonexistent(self, connection_store):
        """Test getting a connection that doesn't exist."""
        assert connection_store.get("nonexistent") is None

    def test_get_all(self, connection_store):
        """Test retrieving all connections."""
        connection_store.add(make_connection("conn-1"))
        connection_store.add(make_connection("conn-2"))

        assert len(connection_store.get_all()) == 2

    def test_clear(self, connection_store):
        """Test clearing all connections."""
        connection_store.add(make_connection("conn-1"))

        connection_store.clear()

        assert connection_store.get_all() == []
