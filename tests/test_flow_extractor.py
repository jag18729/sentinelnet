"""Tests for the Suricata EVE flow feature extractor."""

import pytest
import math
import json
import sys
from pathlib import Path

# pipeline/ is not a package; add it to sys.path for direct import
sys.path.insert(0, str(Path(__file__).parent.parent / "pipeline"))

from flow_extractor import (
    FEATURE_NAMES,
    FEATURE_SOURCE,
    FlowFeatures,
    ExtractionStats,
    extract_features,
    extract_from_eve_file,
    _safe_div,
    _parse_timestamp,
)


class TestFeatureConstants:

    def test_25_features_defined(self):
        assert len(FEATURE_NAMES) == 25

    def test_all_features_have_source(self):
        for name in FEATURE_NAMES:
            assert name in FEATURE_SOURCE

    def test_source_types_valid(self):
        valid = {"EXACT", "DERIVED", "UNAVAILABLE"}
        for source in FEATURE_SOURCE.values():
            assert source in valid

    def test_expected_exact_count(self):
        exact = sum(1 for s in FEATURE_SOURCE.values() if s == "EXACT")
        assert exact == 9

    def test_expected_derived_count(self):
        derived = sum(1 for s in FEATURE_SOURCE.values() if s == "DERIVED")
        assert derived == 7

    def test_expected_unavailable_count(self):
        unavail = sum(1 for s in FEATURE_SOURCE.values() if s == "UNAVAILABLE")
        assert unavail == 9


class TestSafeDiv:

    def test_normal_division(self):
        assert _safe_div(10, 2) == 5.0

    def test_zero_denominator(self):
        assert _safe_div(10, 0) == 0.0

    def test_custom_default(self):
        assert _safe_div(10, 0, default=-1.0) == -1.0


class TestParseTimestamp:

    def test_valid_iso_timestamp(self):
        ts = "2026-02-16T18:25:21.511588+00:00"
        result = _parse_timestamp(ts)
        assert result > 0

    def test_invalid_timestamp(self):
        assert _parse_timestamp("not-a-date") == 0.0

    def test_none_input(self):
        assert _parse_timestamp(None) == 0.0


class TestExtractFeatures:

    @pytest.fixture
    def sample_eve_record(self):
        return {
            "timestamp": "2026-03-25T10:00:00.000000+00:00",
            "event_type": "flow",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "src_port": 54321,
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": "12345",
            "flow": {
                "pkts_toserver": 10,
                "pkts_toclient": 8,
                "bytes_toserver": 5000,
                "bytes_toclient": 3000,
                "start": "2026-03-25T10:00:00.000000+00:00",
                "end": "2026-03-25T10:00:05.000000+00:00",
                "age": 5,
            },
        }

    def test_returns_flow_features(self, sample_eve_record):
        result = extract_features(sample_eve_record)
        assert isinstance(result, FlowFeatures)

    def test_25_feature_values(self, sample_eve_record):
        result = extract_features(sample_eve_record)
        assert len(result.values) == 25

    def test_metadata_populated(self, sample_eve_record):
        result = extract_features(sample_eve_record)
        assert result.src_ip == "192.168.1.100"
        assert result.dst_ip == "10.0.0.1"
        assert result.src_port == 54321
        assert result.dst_port == 443
        assert result.proto == "TCP"

    def test_exact_features_computed(self, sample_eve_record):
        result = extract_features(sample_eve_record)
        assert result.values[1] == 10.0   # Total Fwd Packets
        assert result.values[2] == 8.0    # Total Backward Packets
        assert result.values[3] == 5000.0 # Total Length of Fwd Packets
        assert result.values[4] == 3000.0 # Total Length of Bwd Packets

    def test_derived_features_computed(self, sample_eve_record):
        result = extract_features(sample_eve_record)
        assert result.values[5] == 500.0  # Fwd Packet Length Mean = 5000/10
        assert result.values[7] == 375.0  # Bwd Packet Length Mean = 3000/8

    def test_unavailable_features_zero(self, sample_eve_record):
        result = extract_features(sample_eve_record)
        assert result.values[6] == 0.0   # Fwd Packet Length Std
        assert result.values[8] == 0.0   # Bwd Packet Length Std
        assert result.values[23] == 0.0  # Active Mean
        assert result.values[24] == 0.0  # Idle Mean

    def test_no_nan_or_inf(self, sample_eve_record):
        result = extract_features(sample_eve_record)
        for v in result.values:
            assert not math.isnan(v)
            assert not math.isinf(v)

    def test_empty_flow_returns_none(self):
        record = {"event_type": "flow", "flow": {}}
        result = extract_features(record)
        assert result is None

    def test_no_flow_key_returns_none(self):
        record = {"event_type": "flow"}
        result = extract_features(record)
        assert result is None

    def test_quality_full_for_good_flows(self, sample_eve_record):
        result = extract_features(sample_eve_record)
        assert result.quality == "full"

    def test_quality_partial_for_short_flows(self):
        record = {
            "event_type": "flow",
            "flow": {
                "pkts_toserver": 1,
                "pkts_toclient": 1,
                "bytes_toserver": 100,
                "bytes_toclient": 50,
                "start": "2026-03-25T10:00:00.000000+00:00",
                "end": "2026-03-25T10:00:00.000000+00:00",
                "age": 0,
            },
        }
        result = extract_features(record)
        assert result.quality == "partial"

    def test_to_dict(self, sample_eve_record):
        result = extract_features(sample_eve_record)
        d = result.to_dict()
        assert "features" in d
        assert "metadata" in d
        assert len(d["features"]) == 25


class TestExtractionStats:

    def test_initial_values(self):
        stats = ExtractionStats()
        assert stats.total == 0
        assert stats.success == 0

    def test_summary(self):
        stats = ExtractionStats(total=10, success=8, skipped_no_packets=2)
        s = stats.summary()
        assert s["total_processed"] == 10
        assert s["successful"] == 8
        assert s["success_rate"] == "80.0%"


class TestExtractFromEveFile:

    def test_extract_from_file(self, tmp_path):
        eve_path = tmp_path / "eve.json"
        records = [
            {
                "event_type": "flow",
                "flow": {
                    "pkts_toserver": 5,
                    "pkts_toclient": 3,
                    "bytes_toserver": 2000,
                    "bytes_toclient": 1000,
                    "start": "2026-03-25T10:00:00.000000+00:00",
                    "end": "2026-03-25T10:00:02.000000+00:00",
                    "age": 2,
                },
            },
            {
                "event_type": "alert",
                "alert": {"signature": "test"},
            },
            {
                "event_type": "flow",
                "flow": {
                    "pkts_toserver": 1,
                    "pkts_toclient": 0,
                    "bytes_toserver": 60,
                    "bytes_toclient": 0,
                    "age": 0,
                },
            },
        ]
        with open(eve_path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        features, stats = extract_from_eve_file(str(eve_path), min_packets=2)
        assert stats.total == 2  # 2 flow events
        assert stats.success == 1  # only first has enough packets
        assert len(features) == 1

    def test_max_records(self, tmp_path):
        eve_path = tmp_path / "eve.json"
        with open(eve_path, "w") as f:
            for i in range(10):
                r = {
                    "event_type": "flow",
                    "flow": {
                        "pkts_toserver": 5,
                        "pkts_toclient": 5,
                        "bytes_toserver": 1000,
                        "bytes_toclient": 1000,
                        "age": 1,
                    },
                }
                f.write(json.dumps(r) + "\n")

        features, stats = extract_from_eve_file(str(eve_path), max_records=3)
        assert len(features) == 3
