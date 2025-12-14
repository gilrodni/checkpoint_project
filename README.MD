# AI-Driven Firewall Backend

A FastAPI REST service for AI-driven network security with policy-based access control and anomaly detection.

## Features

- **Connection Evaluation**: Submit network connections for security analysis
- **Policy Management**: Define and manage security policies with flexible conditions
- **AI Anomaly Detection**: Simulated AI-based anomaly scoring (0-1 scale)
- **Decision Engine**: Automatic security decisions (allow/alert/block) based on policies and anomaly scores

## Architecture

The service consists of three main components:

1. **Policy Engine**: Evaluates connections against policies in insertion order
2. **Anomaly Detector**: Generates random anomaly scores (simulated AI)
3. **Storage**: In-memory storage for policies and connection decisions

### Decision Logic

1. Get anomaly score from AI service
2. Evaluate connection against policies in insertion order
3. Apply action of first matched policy (default: block if no match)
4. **Anomaly Exception**: If `anomaly_score > 0.8` and action is `allow`, escalate to `alert`

## Setup

### Prerequisites

- Python 3.12+

### Installation

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -e .
```

### Running the Server

```bash
cd src
python main.py
```

Or using uvicorn directly:

```bash
cd src
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

### API Documentation

Once running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## API Endpoints

### POST /policies - Create a Security Policy

```bash
curl -X POST http://localhost:8000/policies \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "P-001",
    "conditions": [
      {"field": "destination_port", "operator": "==", "value": "443"}
    ],
    "action": "allow"
  }'
```

**Response (201 Created):**
```json
{
  "policy_id": "P-001",
  "conditions": [
    {"field": "destination_port", "operator": "==", "value": "443"}
  ],
  "action": "allow"
}
```

### POST /connections - Submit Connection for Evaluation

```bash
curl -X POST http://localhost:8000/connections \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.10",
    "destination_ip": "10.0.0.5",
    "destination_port": 443,
    "protocol": "TCP",
    "timestamp": "2025-04-30T12:34:56Z"
  }'
```

**Response (200 OK):**
```json
{
  "connection_id": "550e8400-e29b-41d4-a716-446655440000",
  "decision": "allow",
  "anomaly_score": 0.42,
  "matched_policy": "P-001"
}
```

### GET /connections/{id} - Get Connection Details

```bash
curl http://localhost:8000/connections/550e8400-e29b-41d4-a716-446655440000
```

**Response (200 OK):**
```json
{
  "connection_id": "550e8400-e29b-41d4-a716-446655440000",
  "source_ip": "192.168.1.10",
  "destination_ip": "10.0.0.5",
  "destination_port": 443,
  "protocol": "TCP",
  "timestamp": "2025-04-30T12:34:56Z",
  "decision": "allow",
  "anomaly_score": 0.42,
  "matched_policy": "P-001"
}
```

### GET /policies - List All Policies

```bash
curl http://localhost:8000/policies
```

### DELETE /policies/{id} - Delete a Policy

```bash
curl -X DELETE http://localhost:8000/policies/P-001
```

## Policy Conditions

Supported fields:
- `source_ip`
- `destination_ip`
- `destination_port`
- `protocol`

Supported operators:
- `==` (equals)
- `!=` (not equals)
- `>` (greater than)
- `<` (less than)
- `>=` (greater or equal)
- `<=` (less or equal)
- `in` (value in comma-separated list)

### Example: Multiple Conditions

```bash
curl -X POST http://localhost:8000/policies \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "P-002",
    "conditions": [
      {"field": "destination_port", "operator": "==", "value": "443"},
      {"field": "source_ip", "operator": "==", "value": "192.168.1.10"}
    ],
    "action": "block"
  }'
```

## Anomaly Detection

The service uses simulated AI-based anomaly scoring:
- Scores range from 0 to 1
- Higher scores indicate higher likelihood of anomalous activity
- Currently implemented using `random.random()` for simulation

**Anomaly Exception Rule**: If `anomaly_score > 0.8` and the matched policy action is `allow`, the decision is escalated to `alert`.

## Design Decisions

1. **In-Memory Storage**: Policies and connections are stored in RAM for simplicity. Can be extended to use a database.

2. **Insertion-Order Evaluation**: Policies are evaluated in the order they were created using `OrderedDict`.

3. **Simulated AI Scoring**: Random scoring provides realistic variation for testing without external dependencies.

4. **Default Block**: Connections that don't match any policy are blocked by default (secure by default).

## Known Limitations

- Data is lost on server restart (in-memory storage)
- No authentication/authorization
- No connection deduplication

## Future Improvements

- Add database persistence (PostgreSQL/Redis)
- Implement real AI/ML anomaly detection
- Add authentication and rate limiting
- Connection logging and analytics
- Policy versioning and audit trail

