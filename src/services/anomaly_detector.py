"""AI anomaly detection service using simulated random scoring."""

import random


class AnomalyDetector:
    """Simulated AI anomaly detection service.
    
    Generates random anomaly scores between 0 and 1 to simulate
    AI-based anomaly detection.
    """
    
    def get_score(self) -> float:
        """Get a random anomaly score.
        
        Returns:
            A float between 0 and 1, where higher values indicate
            higher likelihood of anomalous/malicious activity.
        """
        return random.random()


# Global detector instance
anomaly_detector = AnomalyDetector()

