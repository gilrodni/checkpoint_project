"""Integration tests for FastAPI endpoints."""

from unittest.mock import patch


class TestPoliciesEndpoint:
    """Integration tests for /policies endpoints."""

    def test_create_policy(self, test_client):
        """Test creating a new policy."""
        policy_data = {
            "policy_id": "test-policy",
            "conditions": [
                {"field": "destination_port", "operator": "==", "value": "443"}
            ],
            "action": "allow",
        }

        response = test_client.post("/policies", json=policy_data)

        assert response.status_code == 201
        data = response.json()
        assert data["policy_id"] == "test-policy"
        assert data["action"] == "allow"
        assert len(data["conditions"]) == 1

    def test_list_policies_empty(self, test_client):
        """Test listing policies when none exist."""
        response = test_client.get("/policies")

        assert response.status_code == 200
        assert response.json() == []

    def test_list_policies(self, test_client):
        """Test listing policies after creating some."""
        # Create two policies
        test_client.post(
            "/policies",
            json={
                "policy_id": "policy-1",
                "conditions": [],
                "action": "allow",
            },
        )
        test_client.post(
            "/policies",
            json={
                "policy_id": "policy-2",
                "conditions": [],
                "action": "block",
            },
        )

        response = test_client.get("/policies")

        assert response.status_code == 200
        policies = response.json()
        assert len(policies) == 2
        assert policies[0]["policy_id"] == "policy-1"
        assert policies[1]["policy_id"] == "policy-2"

    def test_delete_policy(self, test_client):
        """Test deleting an existing policy."""
        # Create a policy first
        test_client.post(
            "/policies",
            json={
                "policy_id": "to-delete",
                "conditions": [],
                "action": "allow",
            },
        )

        response = test_client.delete("/policies/to-delete")

        assert response.status_code == 204

        # Verify it's gone
        list_response = test_client.get("/policies")
        assert len(list_response.json()) == 0

    def test_delete_nonexistent_policy(self, test_client):
        """Test deleting a policy that doesn't exist."""
        response = test_client.delete("/policies/nonexistent")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestConnectionsEndpoint:
    """Integration tests for /connections endpoints."""

    def test_submit_connection_no_policy_blocks(self, test_client):
        """Test that connections with no matching policy are blocked."""
        connection_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": "2024-01-15T10:30:00",
        }

        response = test_client.post("/connections", json=connection_data)

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "block"
        assert data["matched_policy"] is None
        assert "connection_id" in data
        assert "anomaly_score" in data

    def test_submit_connection_with_matching_policy(self, test_client):
        """Test connection with matching allow policy."""
        # Create allow policy for port 443
        test_client.post(
            "/policies",
            json={
                "policy_id": "allow-https",
                "conditions": [
                    {"field": "destination_port", "operator": "==", "value": "443"}
                ],
                "action": "allow",
            },
        )

        connection_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": "2024-01-15T10:30:00",
        }

        # Mock anomaly detector to return low score
        with patch("main.anomaly_detector.get_score", return_value=0.1):
            response = test_client.post("/connections", json=connection_data)

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "allow"
        assert data["matched_policy"] == "allow-https"

    def test_submit_connection_anomaly_escalates_to_alert(self, test_client):
        """Test that high anomaly score escalates allow to alert."""
        # Create allow policy
        test_client.post(
            "/policies",
            json={
                "policy_id": "allow-all-tcp",
                "conditions": [{"field": "protocol", "operator": "==", "value": "TCP"}],
                "action": "allow",
            },
        )

        connection_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": "2024-01-15T10:30:00",
        }

        # Mock high anomaly score (> 0.8)
        with patch("main.anomaly_detector.get_score", return_value=0.95):
            response = test_client.post("/connections", json=connection_data)

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "alert"  # Escalated from allow

    def test_submit_connection_block_not_escalated(self, test_client):
        """Test that block decisions are not affected by anomaly score."""
        # Create block policy
        test_client.post(
            "/policies",
            json={
                "policy_id": "block-ip",
                "conditions": [
                    {"field": "source_ip", "operator": "==", "value": "192.168.1.100"}
                ],
                "action": "block",
            },
        )

        connection_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": "2024-01-15T10:30:00",
        }

        # Even with high anomaly, block should stay block
        with patch("main.anomaly_detector.get_score", return_value=0.95):
            response = test_client.post("/connections", json=connection_data)

        assert response.status_code == 200
        assert response.json()["decision"] == "block"

    def test_get_connection_details(self, test_client):
        """Test retrieving connection details by ID."""
        # Submit a connection first
        connection_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
            "protocol": "TCP",
            "timestamp": "2024-01-15T10:30:00",
        }

        with patch("main.anomaly_detector.get_score", return_value=0.5):
            submit_response = test_client.post("/connections", json=connection_data)
        connection_id = submit_response.json()["connection_id"]

        # Retrieve the connection
        response = test_client.get(f"/connections/{connection_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["connection_id"] == connection_id
        assert data["source_ip"] == "192.168.1.100"
        assert data["destination_ip"] == "10.0.0.1"
        assert data["destination_port"] == 80
        assert data["protocol"] == "TCP"

    def test_get_nonexistent_connection(self, test_client):
        """Test getting a connection that doesn't exist."""
        response = test_client.get("/connections/nonexistent-id")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestFullFlow:
    """End-to-end integration tests."""

    def test_policy_priority_order(self, test_client):
        """Test that first matching policy wins."""
        # Create policies in order: first allows port 443, second blocks all TCP
        test_client.post(
            "/policies",
            json={
                "policy_id": "allow-https",
                "conditions": [
                    {"field": "destination_port", "operator": "==", "value": "443"}
                ],
                "action": "allow",
            },
        )
        test_client.post(
            "/policies",
            json={
                "policy_id": "block-tcp",
                "conditions": [{"field": "protocol", "operator": "==", "value": "TCP"}],
                "action": "block",
            },
        )

        connection_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": "2024-01-15T10:30:00",
        }

        with patch("main.anomaly_detector.get_score", return_value=0.1):
            response = test_client.post("/connections", json=connection_data)

        # Should match first policy (allow-https), not second (block-tcp)
        assert response.json()["decision"] == "allow"
        assert response.json()["matched_policy"] == "allow-https"

    def test_multiple_conditions_policy(self, test_client):
        """Test policy with multiple conditions."""
        test_client.post(
            "/policies",
            json={
                "policy_id": "strict-allow",
                "conditions": [
                    {"field": "destination_port", "operator": "==", "value": "443"},
                    {"field": "protocol", "operator": "==", "value": "TCP"},
                    {"field": "destination_ip", "operator": "==", "value": "10.0.0.1"},
                ],
                "action": "allow",
            },
        )

        # Connection that matches all conditions
        matching_connection = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": "2024-01-15T10:30:00",
        }

        with patch("main.anomaly_detector.get_score", return_value=0.1):
            response = test_client.post("/connections", json=matching_connection)

        assert response.json()["decision"] == "allow"

        # Connection that fails one condition
        non_matching_connection = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.2",  # Different IP
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": "2024-01-15T10:30:00",
        }

        response = test_client.post("/connections", json=non_matching_connection)
        assert response.json()["decision"] == "block"  # No policy matches

    def test_ne_operator_in_policy(self, test_client):
        """Test policy using NE (not equals) operator."""
        test_client.post(
            "/policies",
            json={
                "policy_id": "block-non-https",
                "conditions": [
                    {"field": "destination_port", "operator": "!=", "value": "443"}
                ],
                "action": "block",
            },
        )
        test_client.post(
            "/policies",
            json={
                "policy_id": "allow-all",
                "conditions": [],
                "action": "allow",
            },
        )

        # Port 80 should be blocked
        with patch("main.anomaly_detector.get_score", return_value=0.1):
            response = test_client.post(
                "/connections",
                json={
                    "source_ip": "192.168.1.100",
                    "destination_ip": "10.0.0.1",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "timestamp": "2024-01-15T10:30:00",
                },
            )
        assert response.json()["decision"] == "block"

        # Port 443 should be allowed (doesn't match NE condition)
        with patch("main.anomaly_detector.get_score", return_value=0.1):
            response = test_client.post(
                "/connections",
                json={
                    "source_ip": "192.168.1.100",
                    "destination_ip": "10.0.0.1",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "timestamp": "2024-01-15T10:30:00",
                },
            )
        assert response.json()["decision"] == "allow"
