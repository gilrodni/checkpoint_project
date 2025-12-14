"""Pydantic models for the AI-driven firewall API."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Protocol(str, Enum):
    """Supported network protocols."""
    TCP = "TCP"
    UDP = "UDP"


class Action(str, Enum):
    """Security policy actions."""
    ALLOW = "allow"
    ALERT = "alert"
    BLOCK = "block"


class Operator(str, Enum):
    """Comparison operators for policy conditions."""
    EQ = "=="
    NE = "!="
    GT = ">"
    LT = "<"
    GE = ">="
    LE = "<="


class ConnectionRequest(BaseModel):
    """Request model for submitting a network connection."""
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: Protocol
    timestamp: datetime


class ConnectionResponse(BaseModel):
    """Response model for connection evaluation."""
    connection_id: str
    decision: Action
    anomaly_score: float
    matched_policy: Optional[str] = None


class ConnectionDetail(BaseModel):
    """Detailed connection information for GET endpoint."""
    connection_id: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: Protocol
    timestamp: datetime
    decision: Action
    anomaly_score: float
    matched_policy: Optional[str] = None


class PolicyCondition(BaseModel):
    """A single condition in a security policy."""
    field: str
    operator: Operator
    value: str


class PolicyRequest(BaseModel):
    """Request model for creating a security policy."""
    policy_id: str
    conditions: list[PolicyCondition]
    action: Action


class Policy(BaseModel):
    """Stored policy with all details."""
    policy_id: str
    conditions: list[PolicyCondition]
    action: Action

