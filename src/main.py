"""FastAPI application for AI-driven firewall."""

import uuid

from fastapi import FastAPI, HTTPException, status

from models import (
    Action,
    ConnectionDetail,
    ConnectionRequest,
    ConnectionResponse,
    Policy,
    PolicyRequest,
)
from services.anomaly_detector import anomaly_detector
from services.policy_engine import policy_engine
from services.storage import connection_store, policy_store

app = FastAPI(
    title="AI-Driven Firewall",
    description="Backend service for AI-driven network security with policy-based access control",
    version="1.0.0",
)


@app.post(
    "/connections",
    response_model=ConnectionResponse,
    status_code=status.HTTP_200_OK,
)
def submit_connection(request: ConnectionRequest) -> ConnectionResponse:
    """Submit connection data for evaluation.
    
    Evaluates the connection against defined policies and AI anomaly detection,
    then returns a security decision (allow, alert, or block).
    """
    # Generate unique connection ID
    connection_id = str(uuid.uuid4())
    
    # Get anomaly score from AI service
    anomaly_score = anomaly_detector.get_score()
    
    # Evaluate connection against policies
    matched_policy = policy_engine.evaluate(request)
    
    # Determine action based on policy match
    if matched_policy:
        action = matched_policy.action
        matched_policy_id = matched_policy.policy_id
    else:
        # Default to block if no policy matches
        action = Action.BLOCK
        matched_policy_id = None
    
    # Anomaly exception: escalate to alert if score > 0.8 and action is allow
    if anomaly_score > 0.8 and action == Action.ALLOW:
        action = Action.ALERT
    
    # Store connection details
    connection_detail = ConnectionDetail(
        connection_id=connection_id,
        source_ip=request.source_ip,
        destination_ip=request.destination_ip,
        destination_port=request.destination_port,
        protocol=request.protocol,
        timestamp=request.timestamp,
        decision=action,
        anomaly_score=anomaly_score,
        matched_policy=matched_policy_id,
    )
    connection_store.add(connection_detail)
    
    return ConnectionResponse(
        connection_id=connection_id,
        decision=action,
        anomaly_score=round(anomaly_score, 2),
        matched_policy=matched_policy_id,
    )


@app.post(
    "/policies",
    response_model=Policy,
    status_code=status.HTTP_201_CREATED,
)
def create_policy(request: PolicyRequest) -> Policy:
    """Define a new security policy.
    
    Policies are evaluated in insertion order when processing connections.
    """
    policy = Policy(
        policy_id=request.policy_id,
        conditions=request.conditions,
        action=request.action,
    )
    policy_store.add(policy)
    return policy


@app.get(
    "/connections/{connection_id}",
    response_model=ConnectionDetail,
)
def get_connection(connection_id: str) -> ConnectionDetail:
    """Retrieve connection decision details by ID."""
    connection = connection_store.get(connection_id)
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connection {connection_id} not found",
        )
    return connection


@app.get("/policies", response_model=list[Policy])
def list_policies() -> list[Policy]:
    """List all defined policies in insertion order."""
    return policy_store.get_all()


@app.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(policy_id: str) -> None:
    """Delete a policy by ID."""
    if not policy_store.delete(policy_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy {policy_id} not found",
        )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(app, host="0.0.0.0", port=8000)

