"""Metric anomaly detection.

Two detectors, because they catch different failures.

**Robust z-score** uses the median and the median absolute deviation rather than the
mean and standard deviation. The reason is circular but decisive: the mean and standard
deviation are themselves distorted by the outliers being looked for, so a single large
spike inflates the standard deviation enough to hide itself. The median and MAD are
unaffected by up to half the data being garbage.

**Seasonal comparison** checks a point against the same time of day in previous cycles.
Most infrastructure metrics are strongly daily, and a detector without seasonality
alerts every morning when traffic arrives, which is how alerting gets switched off.

Pure Python throughout. These are medians and subtractions; numpy would be a
dependency for arithmetic.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

# Scales MAD to be comparable with a standard deviation for normally distributed data,
# so a threshold of "3" means roughly what people expect it to mean.
_MAD_TO_SIGMA = 1.4826


@dataclass
class Anomaly:
    index: int
    value: float
    score: float
    direction: str  # "high" or "low"
    detector: str
    series: str = ""
    at: float = 0.0


def _validate_numeric(values: list[float], label: str = "values") -> None:
    for i, v in enumerate(values):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError(f"{label}[{i}] is not numeric (got {type(v).__name__} instead: {v!r})")


def median_absolute_deviation(values: list[float]) -> float:
    if not values:
        return 0.0
    med = statistics.median(values)
    return statistics.median([abs(v - med) for v in values])


def robust_z_scores(values: list[float]) -> list[float]:
    """Z-scores computed from median and MAD."""
    if len(values) < 3:
        return [0.0] * len(values)
    med = statistics.median(values)
    mad = median_absolute_deviation(values)
    if mad == 0:
        # A constant series: any departure at all is the signal, and the magnitude
        # is not meaningful. Report a fixed large score rather than dividing by zero.
        return [0.0 if v == med else (10.0 if v > med else -10.0) for v in values]
    return [(v - med) / (mad * _MAD_TO_SIGMA) for v in values]


def detect_outliers(
    values: list[float], *, threshold: float = 3.0, series: str = ""
) -> list[Anomaly]:
    _validate_numeric(values, label=series or "values")
    return [
        Anomaly(
            index=i,
            value=values[i],
            score=round(abs(z), 3),
            direction="high" if z > 0 else "low",
            detector="robust_z",
            series=series,
        )
        for i, z in enumerate(robust_z_scores(values))
        if abs(z) >= threshold
    ]


def detect_seasonal(
    values: list[float], *, period: int, threshold: float = 3.0, series: str = ""
) -> list[Anomaly]:
    """Compare each point against the same phase of previous cycles.

    Needs at least two complete cycles before it will say anything: with one cycle
    there is no "same time yesterday" to compare against, and guessing would produce
    exactly the false alarms this detector exists to prevent.
    """
    _validate_numeric(values, label=series or "values")
    if period < 2 or len(values) < period * 2:
        return []

    found: list[Anomaly] = []
    for i in range(period, len(values)):
        history = values[i % period : i : period]
        if len(history) < 2:
            continue
        med = statistics.median(history)
        mad = median_absolute_deviation(history)
        if mad == 0:
            # A perfectly regular phase. Any departure is the signal - and
            # skipping here would miss the cleanest possible break.
            if values[i] != med:
                found.append(
                    Anomaly(
                        index=i,
                        value=values[i],
                        score=10.0,
                        direction="high" if values[i] > med else "low",
                        detector="seasonal",
                        series=series,
                    )
                )
            continue
        z = (values[i] - med) / (mad * _MAD_TO_SIGMA)
        if abs(z) >= threshold:
            found.append(
                Anomaly(
                    index=i,
                    value=values[i],
                    score=round(abs(z), 3),
                    direction="high" if z > 0 else "low",
                    detector="seasonal",
                    series=series,
                )
            )
    return found


@dataclass
class Detector:
    threshold: float = 3.0
    period: int | None = None
    # Ignore a series that barely moves: a 3-sigma move on a metric that is
    # essentially flat is noise, not an incident.
    min_relative_change: float = 0.10
    history: dict[str, list[float]] = field(default_factory=dict)

    def detect(self, series: str, values: list[float]) -> list[Anomaly]:
        self.history[series] = values
        found = detect_outliers(values, threshold=self.threshold, series=series)
        if self.period:
            seen = {a.index for a in found}
            found += [
                a
                for a in detect_seasonal(
                    values, period=self.period, threshold=self.threshold, series=series
                )
                if a.index not in seen
            ]

        med = statistics.median(values) if values else 0.0
        if med:
            found = [a for a in found if abs(a.value - med) / abs(med) >= self.min_relative_change]
        return sorted(found, key=lambda a: a.index)
