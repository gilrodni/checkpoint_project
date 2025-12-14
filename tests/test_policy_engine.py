"""Unit tests for PolicyEngine."""

from datetime import datetime

import pytest

from models import Action, ConnectionRequest, Operator, Policy, PolicyCondition, Protocol
from services.policy_engine import PolicyEngine
from services.storage import policy_store


@pytest.fixture
def engine():
    """PolicyEngine instance."""
    return PolicyEngine()


@pytest.fixture
def connection():
    """Sample connection for testing."""
    return ConnectionRequest(
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        destination_port=443,
        protocol=Protocol.TCP,
        timestamp=datetime(2024, 1, 15, 10, 30, 0),
    )


class TestGetFieldValue:
    """Tests for PolicyEngine._get_field_value method."""

    @pytest.mark.parametrize("field,expected", [
        ("source_ip", "192.168.1.100"),
        ("destination_ip", "10.0.0.1"),
        ("destination_port", 443),
        ("protocol", "TCP"),  # enum is unwrapped
        ("timestamp", datetime(2024, 1, 15, 10, 30, 0)),
        ("nonexistent", None),
    ])
    def test_get_field_value(self, engine, connection, field, expected):
        """Test extracting field values from connection."""
        assert engine._get_field_value(connection, field) == expected


class TestEvaluateCondition:
    """Tests for PolicyEngine._evaluate_condition method."""

    @pytest.mark.parametrize("field,operator,value,expected", [
        # EQ operator
        ("source_ip", Operator.EQ, "192.168.1.100", True),
        ("source_ip", Operator.EQ, "10.0.0.5", False),
        # NE operator
        ("source_ip", Operator.NE, "10.0.0.5", True),
        ("source_ip", Operator.NE, "192.168.1.100", False),
        # Port comparison (string to int conversion)
        ("destination_port", Operator.EQ, "443", True),
        ("destination_port", Operator.EQ, "80", False),
        ("destination_port", Operator.EQ, "invalid", False),
        # Protocol enum
        ("protocol", Operator.EQ, "TCP", True),
        ("protocol", Operator.EQ, "UDP", False),
        # Nonexistent field
        ("nonexistent", Operator.EQ, "any", False),
    ])
    def test_evaluate_condition(self, engine, connection, field, operator, value, expected):
        """Test condition evaluation with various operators and fields."""
        condition = PolicyCondition(field=field, operator=operator, value=value)
        assert engine._evaluate_condition(connection, condition) is expected


class TestMatchesPolicy:
    """Tests for PolicyEngine._matches_policy method."""

    @pytest.mark.parametrize("conditions,expected", [
        # Single matching condition
        ([("destination_port", Operator.EQ, "443")], True),
        # Single non-matching condition
        ([("destination_port", Operator.EQ, "80")], False),
        # Multiple conditions - all match
        ([
            ("destination_port", Operator.EQ, "443"),
            ("protocol", Operator.EQ, "TCP"),
            ("source_ip", Operator.EQ, "192.168.1.100"),
        ], True),
        # Multiple conditions - one fails
        ([
            ("destination_port", Operator.EQ, "443"),
            ("protocol", Operator.EQ, "UDP"),
        ], False),
        # Empty conditions - matches everything
        ([], True),
    ])
    def test_matches_policy(self, engine, connection, conditions, expected):
        """Test policy matching with various condition combinations."""
        policy = Policy(
            policy_id="test",
            conditions=[
                PolicyCondition(field=f, operator=op, value=v)
                for f, op, v in conditions
            ],
            action=Action.ALLOW,
        )
        assert engine._matches_policy(connection, policy) is expected


class TestEvaluate:
    """Tests for PolicyEngine.evaluate method."""

    def test_no_policies_returns_none(self, engine, connection):
        """Test that no policies returns None."""
        assert engine.evaluate(connection) is None

    def test_matching_policy_returned(self, engine, connection):
        """Test that matching policy is returned."""
        policy = Policy(
            policy_id="allow-443",
            conditions=[
                PolicyCondition(field="destination_port", operator=Operator.EQ, value="443")
            ],
            action=Action.ALLOW,
        )
        policy_store.add(policy)

        result = engine.evaluate(connection)

        assert result is not None
        assert result.policy_id == "allow-443"

    def test_first_matching_policy_wins(self, engine, connection):
        """Test that first matching policy in order is returned."""
        policy_store.add(Policy(
            policy_id="first-policy",
            conditions=[PolicyCondition(field="protocol", operator=Operator.EQ, value="TCP")],
            action=Action.ALLOW,
        ))
        policy_store.add(Policy(
            policy_id="second-policy",
            conditions=[PolicyCondition(field="destination_port", operator=Operator.EQ, value="443")],
            action=Action.BLOCK,
        ))

        result = engine.evaluate(connection)

        assert result.policy_id == "first-policy"
        assert result.action == Action.ALLOW

    def test_non_matching_policies_skipped(self, engine, connection):
        """Test that non-matching policies are skipped."""
        policy_store.add(Policy(
            policy_id="udp-only",
            conditions=[PolicyCondition(field="protocol", operator=Operator.EQ, value="UDP")],
            action=Action.BLOCK,
        ))
        policy_store.add(Policy(
            policy_id="tcp-allow",
            conditions=[PolicyCondition(field="protocol", operator=Operator.EQ, value="TCP")],
            action=Action.ALLOW,
        ))

        result = engine.evaluate(connection)

        assert result.policy_id == "tcp-allow"
