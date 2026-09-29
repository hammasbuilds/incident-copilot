"""Incident copilot tests.

Synthetic telemetry, so each failure mode — a spike, a seasonal morning rush, a flat
series, a deploy followed by four simultaneous alarms — can be constructed exactly and
asserted on rather than waited for.
"""

from __future__ import annotations

import pytest

from copilot.correlate.incident import ChangeEvent, Signal, correlate
from copilot.logs.drain import DrainParser, mask
from copilot.metrics.anomaly import (
    Detector,
    detect_outliers,
    detect_seasonal,
    median_absolute_deviation,
    robust_z_scores,
)


class TestMasking:
    @pytest.mark.parametrize(
        ("raw", "token"),
        [
            ("from 10.0.0.4 now", "<IP>"),
            ("id 550e8400-e29b-41d4-a716-446655440000 ok", "<UUID>"),
            ("addr 0xdeadbeef here", "<HEX>"),
            ("took 3021ms total", "<NUM>"),
            ("mail a.b@c.com sent", "<EMAIL>"),
            ("read /var/log/app/x.log done", "<PATH>"),
            (r"read C:\Users\ops\app.log done", "<PATH>"),
            ("value is 1.5e10 units", "<NUM>"),
        ],
    )
    def test_variables_are_masked(self, raw, token):
        assert token in mask(raw)

    def test_stable_words_survive(self):
        assert "Connection" in mask("Connection to db-7 failed after 3021ms")

    def test_windows_path_username_does_not_leak_into_the_template(self):
        """A username/hostname embedded in a Windows path must not survive masking,
        or two lines differing only by that path can never collapse to one template."""
        assert "ops" not in mask(r"read C:\Users\ops\app.log done")

    def test_mask_rejects_non_string_input(self):
        with pytest.raises(TypeError):
            mask(None)


class TestDrain:
    def test_varying_lines_collapse_to_one_template(self):
        """A million log lines are a few hundred templates. That is the whole point."""
        p = DrainParser()
        p.parse(
            [
                "Connection to db-7 failed after 3021ms",
                "Connection to db-2 failed after 1180ms",
                "Connection to db-9 failed after 88ms",
            ]
        )
        templates = p.templates()
        assert len(templates) == 1
        assert templates[0].count == 3

    def test_genuinely_different_lines_stay_separate(self):
        p = DrainParser()
        p.parse(
            [
                "Connection to db-7 failed after 3021ms",
                "User 4821 logged in from 10.0.0.4",
                "Cache miss for key user:99:profile",
            ]
        )
        assert len(p.templates()) == 3

    def test_variable_positions_become_wildcards(self):
        p = DrainParser()
        p.parse(["service alpha restarted", "service beta restarted"])
        assert "<*>" in p.templates()[0].text

    def test_examples_are_kept_but_bounded(self):
        """An operator needs a concrete line; they do not need ten thousand."""
        p = DrainParser()
        p.parse([f"Connection to db-{i} failed after {i}ms" for i in range(50)])
        assert len(p.templates()[0].examples) <= 3

    def test_counts_are_accurate(self):
        p = DrainParser()
        p.parse(["disk 1 full"] * 7 + ["cpu 2 hot"] * 3)
        assert {t.count for t in p.templates()} == {7, 3}

    def test_an_unseen_shape_matches_nothing(self):
        """Often the first sign of a new fault: a line unlike anything before it."""
        p = DrainParser()
        p.parse(["Connection to db-7 failed after 3021ms"])
        assert p.match("Kernel panic: unable to mount root filesystem") is None

    def test_a_known_shape_matches(self):
        p = DrainParser()
        p.parse(["Connection to db-7 failed after 3021ms"])
        assert p.match("Connection to db-4 failed after 12ms") is not None

    def test_empty_input(self):
        assert DrainParser().parse([]) == []

    def test_blank_lines_are_ignored(self):
        p = DrainParser()
        p.parse(["", "   ", "real line here"])
        assert len(p.templates()) == 1

    def test_parse_rejects_a_non_string_line_with_its_index(self):
        """A None in a batch of real log lines is a plausible real input, and the
        failure has to say which line, not just crash with an AttributeError."""
        with pytest.raises(TypeError, match="line 1"):
            DrainParser().parse(["a real line", None, "another line"])

    def test_add_rejects_a_non_string_line(self):
        with pytest.raises(TypeError):
            DrainParser().add(123)


class TestRobustStatistics:
    def test_a_single_spike_does_not_hide_itself(self):
        """With mean and standard deviation it would: one large value inflates the
        deviation enough to make itself look ordinary."""
        values = [10.0] * 50 + [1000.0]
        assert abs(robust_z_scores(values)[-1]) > 5

    def test_mad_ignores_outliers(self):
        clean = [10.0, 10.0, 10.0, 10.0, 10.0]
        dirty = [10.0, 10.0, 10.0, 10.0, 9999.0]
        assert median_absolute_deviation(clean) == median_absolute_deviation(dirty)

    def test_short_series_gives_no_verdict(self):
        assert robust_z_scores([1.0, 5.0]) == [0.0, 0.0]

    def test_a_constant_series_does_not_divide_by_zero(self):
        scores = robust_z_scores([5.0] * 20 + [7.0])
        assert scores[-1] > 0 and all(s == 0.0 for s in scores[:-1])


class TestOutlierDetection:
    def test_spike_is_detected(self):
        found = detect_outliers([10.0] * 50 + [500.0], threshold=3.0)
        assert len(found) == 1 and found[0].direction == "high"

    def test_drop_is_detected(self):
        """Traffic falling to zero is an incident too, and a one-sided detector
        misses the outage entirely."""
        found = detect_outliers([100.0] * 50 + [0.0], threshold=3.0)
        assert found and found[0].direction == "low"

    def test_normal_variation_is_not_flagged(self):
        assert detect_outliers([10.0 + (i % 5) for i in range(100)], threshold=3.0) == []

    def test_a_non_numeric_value_raises_a_clear_error(self):
        """A stray string in a metric series is a plausible real input, and the
        failure has to name the offending index rather than a bare TypeError from
        deep inside the arithmetic."""
        with pytest.raises(ValueError, match=r"\[2\]"):
            detect_outliers([1.0, 2.0, "3.0", 4.0])


class TestSeasonality:
    def test_a_daily_pattern_is_not_an_anomaly(self):
        """A detector without seasonality alerts every morning when traffic arrives,
        which is how alerting gets switched off."""
        day = [10, 10, 10, 80, 90, 80, 10, 10] * 5
        assert detect_seasonal([float(v) for v in day], period=8, threshold=3.0) == []

    def test_a_break_in_the_pattern_is_detected(self):
        day = [10, 10, 10, 80, 90, 80, 10, 10] * 4
        day += [10, 10, 10, 5, 90, 80, 10, 10]  # the morning peak did not happen
        found = detect_seasonal([float(v) for v in day], period=8, threshold=3.0)
        assert any(a.direction == "low" for a in found)

    def test_less_than_two_cycles_gives_no_verdict(self):
        """With one cycle there is no 'same time yesterday' to compare against."""
        assert detect_seasonal([1.0, 2.0, 3.0, 4.0], period=4) == []

    def test_a_non_numeric_value_raises_a_clear_error(self):
        values = [1.0] * 16
        values[5] = None
        with pytest.raises(ValueError, match=r"\[5\]"):
            detect_seasonal(values, period=8)


class TestDetector:
    def test_tiny_relative_moves_are_suppressed(self):
        """A 3-sigma move on a metric that barely moves is noise, not an incident."""
        values = [100.0] * 50 + [100.5]
        assert Detector(threshold=3.0, min_relative_change=0.10).detect("cpu", values) == []

    def test_a_real_move_survives_the_filter(self):
        values = [100.0] * 50 + [400.0]
        assert Detector(threshold=3.0, min_relative_change=0.10).detect("cpu", values)

    def test_detectors_do_not_double_report_the_same_point(self):
        values = ([10.0] * 8) * 4 + [10.0] * 7 + [900.0]
        found = Detector(threshold=3.0, period=8).detect("qps", values)
        assert len({a.index for a in found}) == len(found)

    def test_a_non_numeric_reading_raises_a_clear_error(self):
        """detect() is the main entry point; a bad reading in a metric stream is a
        plausible real input and must not surface as a bare TypeError from a
        division deep inside robust_z_scores."""
        with pytest.raises(ValueError, match=r"\[2\]"):
            Detector().detect("qps", [1.0, 2.0, "oops", 4.0])


class TestCorrelation:
    def test_simultaneous_signals_become_one_incident(self):
        """One deploy causes four alarms. Paging someone four times is how alert
        fatigue starts."""
        signals = [
            Signal(at=1000, service="api", kind="metric", detail="latency high", score=8),
            Signal(at=1010, service="api", kind="metric", detail="errors high", score=9),
            Signal(at=1020, service="db", kind="metric", detail="connections high", score=7),
            Signal(at=1030, service="api", kind="log", detail="timeout template", score=5),
        ]
        assert len(correlate(signals, window_seconds=300)) == 1

    def test_distant_signals_are_separate_incidents(self):
        signals = [
            Signal(at=1000, service="api", kind="metric", detail="a"),
            Signal(at=99_000, service="api", kind="metric", detail="b"),
        ]
        assert len(correlate(signals, window_seconds=300)) == 2

    def test_grouping_is_by_gap_not_fixed_buckets(self):
        """A fixed window splits one incident in two whenever it straddles a boundary."""
        signals = [
            Signal(at=1000 + i * 200, service="api", kind="metric", detail=str(i))
            for i in range(10)
        ]
        assert len(correlate(signals, window_seconds=300)) == 1

    def test_a_preceding_change_is_attached(self):
        signals = [Signal(at=2000, service="api", kind="metric", detail="latency", score=9)]
        changes = [ChangeEvent(at=1900, kind="deploy", description="api v2.3", service="api")]
        assert correlate(signals, changes)[0].causes[0].description == "api v2.3"

    def test_a_change_after_the_onset_is_not_a_cause(self):
        """It is a response. Presenting it as a cause sends the investigation
        backwards."""
        signals = [Signal(at=2000, service="api", kind="metric", detail="latency")]
        changes = [ChangeEvent(at=2100, kind="deploy", description="the rollback")]
        assert correlate(signals, changes)[0].causes == []

    def test_an_unrelated_service_change_is_not_attached(self):
        signals = [Signal(at=2000, service="api", kind="metric", detail="latency")]
        changes = [ChangeEvent(at=1900, kind="deploy", description="billing v1", service="billing")]
        assert correlate(signals, changes)[0].causes == []

    def test_causes_are_most_recent_first(self):
        signals = [Signal(at=2000, service="api", kind="metric", detail="x")]
        changes = [
            ChangeEvent(at=1000, kind="deploy", description="old"),
            ChangeEvent(at=1950, kind="deploy", description="recent"),
        ]
        assert correlate(signals, changes)[0].causes[0].description == "recent"

    def test_no_signals_means_no_incidents(self):
        assert correlate([]) == []

    def test_an_unscoped_change_is_attached_to_any_service(self):
        """Documented behaviour: a ChangeEvent with no `service` set is treated as
        global and can be a candidate cause for any incident in the lookback
        window - the right call for a genuinely infrastructure-wide change, and
        the reason a per-service change should always set `service`."""
        signals = [Signal(at=2000, service="api", kind="metric", detail="latency")]
        changes = [ChangeEvent(at=1900, kind="config", description="cdn cache ttl")]
        assert correlate(signals, changes)[0].causes[0].description == "cdn cache ttl"


class TestSeverity:
    def test_breadth_outranks_strength(self):
        """One metric at 10 sigma on one service is usually that service. Three
        services moving together is usually infrastructure."""
        narrow = correlate([Signal(at=1, service="api", kind="metric", detail="x", score=10.0)])[0]
        broad = correlate(
            [
                Signal(at=1, service="api", kind="metric", detail="x", score=3.1),
                Signal(at=2, service="db", kind="metric", detail="y", score=3.2),
                Signal(at=3, service="cache", kind="metric", detail="z", score=3.3),
            ]
        )[0]
        assert narrow.severity == "high"
        assert broad.severity == "critical"

    def test_summary_is_operator_readable(self):
        incident = correlate(
            [Signal(at=1000, service="api", kind="metric", detail="latency high", score=9)],
            [ChangeEvent(at=990, kind="deploy", description="api v2.3", service="api")],
        )[0]
        s = incident.summary()
        assert s["services"] == ["api"]
        assert "deploy: api v2.3" in s["causes"]
        assert "latency high" in s["top_signals"][0]
