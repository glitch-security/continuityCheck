import math
from typing import Optional


def compute_anomaly(current_size: int, historical_sizes: list[int]) -> Optional[dict]:
    if len(historical_sizes) < 5:
        return None

    n = len(historical_sizes)
    mean = sum(historical_sizes) / n
    variance = sum((x - mean) ** 2 for x in historical_sizes) / n
    std = math.sqrt(variance)

    if std == 0:
        if current_size != int(mean):
            return {
                "anomaly": True,
                "mean": mean,
                "std": 0,
                "current": current_size,
                "deviation_factor": float("inf"),
                "description": f"Response size changed from fixed {int(mean)} bytes to {current_size} bytes",
            }
        return None

    deviation = abs(current_size - mean) / std
    if deviation > 2.0:
        direction = "increased" if current_size > mean else "decreased"
        return {
            "anomaly": True,
            "mean": round(mean, 1),
            "std": round(std, 1),
            "current": current_size,
            "deviation_factor": round(deviation, 2),
            "description": (
                f"Response size {direction} anomalously: "
                f"{current_size} bytes vs avg {int(mean)} bytes "
                f"(±{int(std)}, {round(deviation, 1)}σ deviation)"
            ),
        }

    return None
