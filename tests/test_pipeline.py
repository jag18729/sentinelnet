"""Tests for the exfil detection pipeline components."""

import time
import json
import collections
import pytest
import sys
from pathlib import Path

# pipeline/ is not a package; add it to sys.path for direct import
sys.path.insert(0, str(Path(__file__).parent.parent / "pipeline"))

from pipeline import PipelineMetrics, Whitelist, AlertRouter
from flow_extractor import FlowFeatures


class TestPipelineMetrics:

    def test_initial_values(self):
        m = PipelineMetrics()
        assert m.flows_read == 0
        assert m.batches_sent == 0
        assert m.api_errors == 0

    def test_summary_contains_keys(self):
        m = PipelineMetrics()
        m.flows_read = 100
        m.batches_sent = 5
        s = m.summary()
        assert "uptime_s" in s
        assert "flows_read" in s
        assert s["flows_read"] == 100
        assert s["batches_sent"] == 5

    def test_flows_per_sec(self):
        m = PipelineMetrics()
        m.started_at = time.time() - 10
        m.flows_read = 50
        s = m.summary()
        assert s["flows_per_sec"] == pytest.approx(5.0, abs=1.0)


class TestWhitelist:

    def test_no_file_loads_empty(self, tmp_path):
        wl = Whitelist(str(tmp_path / "nonexistent.json"))
        assert len(wl.rules) == 0

    def test_loads_rules(self, tmp_path):
        wl_path = tmp_path / "whitelist.json"
        wl_path.write_text(json.dumps({
            "rules": [
                {"name": "dns", "dst_port": 53},
                {"name": "ntp", "dst_port": 123},
            ]
        }))
        wl = Whitelist(str(wl_path))
        assert len(wl.rules) == 2

    def test_matches_by_dst_port(self, tmp_path):
        wl_path = tmp_path / "whitelist.json"
        wl_path.write_text(json.dumps({
            "rules": [{"name": "dns", "dst_port": 53}]
        }))
        wl = Whitelist(str(wl_path))

        flow = FlowFeatures(dst_port=53, src_ip="1.1.1.1", dst_ip="8.8.8.8", proto="UDP")
        assert wl.matches(flow) == "dns"

    def test_no_match(self, tmp_path):
        wl_path = tmp_path / "whitelist.json"
        wl_path.write_text(json.dumps({
            "rules": [{"name": "dns", "dst_port": 53}]
        }))
        wl = Whitelist(str(wl_path))

        flow = FlowFeatures(dst_port=443, src_ip="1.1.1.1", dst_ip="8.8.8.8", proto="TCP")
        assert wl.matches(flow) is None

    def test_matches_by_src_ip(self, tmp_path):
        wl_path = tmp_path / "whitelist.json"
        wl_path.write_text(json.dumps({
            "rules": [{"name": "trusted", "src_ip": "10.0.0.1"}]
        }))
        wl = Whitelist(str(wl_path))

        flow = FlowFeatures(dst_port=8080, src_ip="10.0.0.1", dst_ip="1.2.3.4", proto="TCP")
        assert wl.matches(flow) == "trusted"


class TestAlertRouter:

    def test_rate_limit_cooldown(self):
        router = AlertRouter.__new__(AlertRouter)
        router.cooldown = {}
        router.alert_count_window = collections.deque()
        router.metrics = PipelineMetrics()

        assert router._rate_ok("1.1.1.1:2.2.2.2") is True
        assert router._rate_ok("1.1.1.1:2.2.2.2") is False
        assert router.metrics.alerts_suppressed == 1

    def test_different_pairs_not_throttled(self):
        router = AlertRouter.__new__(AlertRouter)
        router.cooldown = {}
        router.alert_count_window = collections.deque()
        router.metrics = PipelineMetrics()

        assert router._rate_ok("1.1.1.1:2.2.2.2") is True
        assert router._rate_ok("3.3.3.3:4.4.4.4") is True


class TestSuricataBridge:

    def test_eve_flow_to_cicids_shape(self):
        from inference.suricata_bridge import eve_flow_to_cicids
        event = {
            "dest_port": 443,
            "flow": {
                "pkts_toserver": 10,
                "pkts_toclient": 8,
                "bytes_toserver": 5000,
                "bytes_toclient": 3000,
                "age": 5,
            },
        }
        features = eve_flow_to_cicids(event)
        assert features.shape == (78,)

    def test_eve_flow_maps_key_features(self):
        from inference.suricata_bridge import eve_flow_to_cicids
        event = {
            "dest_port": 80,
            "flow": {
                "pkts_toserver": 20,
                "pkts_toclient": 15,
                "bytes_toserver": 10000,
                "bytes_toclient": 8000,
                "age": 10,
            },
        }
        features = eve_flow_to_cicids(event)
        assert features[0] == 80        # Destination Port
        assert features[2] == 20        # Total Fwd Packets
        assert features[3] == 15        # Total Backward Packets
        assert features[4] == 10000     # Total Length of Fwd Packets
        assert features[5] == 8000      # Total Length of Bwd Packets

    def test_eve_flow_zero_age(self):
        from inference.suricata_bridge import eve_flow_to_cicids
        event = {
            "dest_port": 443,
            "flow": {
                "pkts_toserver": 1,
                "pkts_toclient": 0,
                "bytes_toserver": 60,
                "bytes_toclient": 0,
                "age": 0,
            },
        }
        features = eve_flow_to_cicids(event)
        assert features[14] == 0.0  # Flow Bytes/s (not inf)
