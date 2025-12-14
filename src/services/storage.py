"""In-memory storage for policies and connections."""

from collections import OrderedDict
from typing import Optional

from models import ConnectionDetail, Policy


class PolicyStore:
    """In-memory storage for security policies.
    
    Uses OrderedDict to maintain insertion order for policy evaluation.
    """
    
    def __init__(self) -> None:
        self._policies: OrderedDict[str, Policy] = OrderedDict()
    
    def add(self, policy: Policy) -> None:
        """Add or update a policy."""
        self._policies[policy.policy_id] = policy
    
    def get(self, policy_id: str) -> Optional[Policy]:
        """Get a policy by ID."""
        return self._policies.get(policy_id)
    
    def get_all(self) -> list[Policy]:
        """Get all policies in insertion order."""
        return list(self._policies.values())
    
    def delete(self, policy_id: str) -> bool:
        """Delete a policy by ID. Returns True if deleted."""
        if policy_id in self._policies:
            del self._policies[policy_id]
            return True
        return False
    
    def clear(self) -> None:
        """Clear all policies."""
        self._policies.clear()


class ConnectionStore:
    """In-memory storage for connection decisions."""
    
    def __init__(self) -> None:
        self._connections: dict[str, ConnectionDetail] = {}
    
    def add(self, connection: ConnectionDetail) -> None:
        """Store a connection decision."""
        self._connections[connection.connection_id] = connection
    
    def get(self, connection_id: str) -> Optional[ConnectionDetail]:
        """Get a connection by ID."""
        return self._connections.get(connection_id)
    
    def get_all(self) -> list[ConnectionDetail]:
        """Get all stored connections."""
        return list(self._connections.values())
    
    def clear(self) -> None:
        """Clear all connections."""
        self._connections.clear()


# Global store instances
policy_store = PolicyStore()
connection_store = ConnectionStore()

