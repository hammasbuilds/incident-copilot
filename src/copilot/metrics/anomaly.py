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

import bisect
import math
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
        if not math.isfinite(v):
            # NaN poisons every median and comparison: an all-NaN series used to
            # come back as "no anomalies", which reads as "all clear".
            raise ValueError(f"{label}[{i}] is {v!r}; drop or fill missing points before detection")
    if not values:
        raise ValueError(f"{label} is empty; there is nothing to detect anomalies in")


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

    # Scale: the per-phase MAD alone is estimated from only a handful of cycles
    # (two weeks of hourly data gives at most 13 samples per phase, and the first
    # cycles give 2-3). On plain Gaussian noise that MAD regularly collapses towards
    # zero and a 1.8-sigma wobble scored 14 - or 100,000 with two samples. So the
    # scale is floored by a pooled one: the median absolute residual of every
    # earlier point against its own phase median, which is estimated from all
    # phases together and is stable after a single cycle.
    pooled: list[float] = []  # sorted |residuals| of earlier points
    found: list[Anomaly] = []
    for i in range(period, len(values)):
        history = values[i % period : i : period]
        med = statistics.median(history)
        residual = values[i] - med
        if len(history) >= 2 and pooled:
            phase_scale = median_absolute_deviation(history) * _MAD_TO_SIGMA
            pooled_scale = _sorted_median(pooled) * _MAD_TO_SIGMA
            scale = max(phase_scale, pooled_scale)
            if scale == 0:
                # Perfectly regular history everywhere. Any departure is the
                # signal - skipping here would miss the cleanest possible break.
                z = 0.0 if residual == 0 else (10.0 if residual > 0 else -10.0)
            else:
                z = residual / scale
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
        bisect.insort(pooled, abs(residual))
    return found


def _sorted_median(xs: list[float]) -> float:
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


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
        if self.period and self.period >= 2 and len(values) >= self.period * 2:
            # On a seasonal series the whole-series median/MAD describe a mixture of
            # day and night levels, so ordinary noise near the low level scores past
            # 3. Score the global outlier test on the series with each phase's
            # median removed instead; values are reported unchanged.
            _validate_numeric(values, label=series or "values")
            phase_med = [statistics.median(values[p :: self.period]) for p in range(self.period)]
            resid = [v - phase_med[i % self.period] for i, v in enumerate(values)]
            found = [
                Anomaly(
                    index=a.index,
                    value=values[a.index],
                    score=a.score,
                    direction=a.direction,
                    detector="robust_z",
                    series=series,
                )
                for a in detect_outliers(resid, threshold=self.threshold, series=series)
            ]
        else:
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
