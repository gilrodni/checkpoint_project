"""Policy evaluation engine for connection matching."""

from typing import Any, Optional

from models import ConnectionRequest, Operator, Policy, PolicyCondition
from services.storage import policy_store


class PolicyEngine:
    """Evaluates connections against security policies.

    Policies are evaluated in insertion order. The first matching
    policy determines the action.
    """

    def _get_field_value(self, connection: ConnectionRequest, field: str) -> Any:
        """Extract a field value from a connection request.

        Supports nested fields using dot notation (e.g., 'protocol.value').
        Automatically unwraps enum values when accessing enum fields directly.
        """
        try:
            value = connection
            for attr in field.split("."):
                value = getattr(value, attr)

            # Automatically unwrap enum values for direct enum field access
            if hasattr(value, "value") and not "." in field:
                return value.value
            return value
        except AttributeError:
            return None

    def _evaluate_condition(
        self, connection: ConnectionRequest, condition: PolicyCondition
    ) -> bool:
        """Evaluate a single condition against a connection."""
        actual_value = self._get_field_value(connection, condition.field)

        if actual_value is None:
            return False

        expected_value = condition.value

        # Convert to appropriate types for comparison
        if condition.field == "destination_port":
            try:
                expected_value = int(expected_value)
            except ValueError:
                return False

        match condition.operator:
            case Operator.EQ:
                return str(actual_value) == str(expected_value)
            case Operator.NE:
                return str(actual_value) != str(expected_value)
            case Operator.GT:
                return actual_value > expected_value
            case Operator.LT:
                return actual_value < expected_value
            case Operator.GE:
                return actual_value >= expected_value
            case Operator.LE:
                return actual_value <= expected_value

    def _matches_policy(self, connection: ConnectionRequest, policy: Policy) -> bool:
        """Check if a connection matches all conditions of a policy."""
        return all(
            self._evaluate_condition(connection, condition)
            for condition in policy.conditions
        )

    def evaluate(self, connection: ConnectionRequest) -> Optional[Policy]:
        """Evaluate a connection against all policies in order.

        Returns the first matching policy, or None if no policy matches.
        """
        for policy in policy_store.get_all():
            if self._matches_policy(connection, policy):
                return policy
        return None


# Global engine instance
policy_engine = PolicyEngine()
