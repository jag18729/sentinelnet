#!/usr/bin/env python3
"""
SentinelNet scapy Traffic Feeder (RV2 / RISC-V)
Captures on end1 (SPAN port) in promiscuous mode, extracts 78 CICFlowMeter-compatible
features per completed flow, POSTs to SentinelNet inference API on Pi2.
"""
import os, time, math, logging, threading, requests
from collections import defaultdict
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, conf

INTERFACE  = os.getenv("FEEDER_INTERFACE", "end1")
INFER_URL  = os.getenv("SENTINELNET_URL", "http://localhost:30800/predict")
IDLE_TO    = int(os.getenv("FEEDER_IDLE_TIMEOUT", "15"))
ACTIVE_TO  = int(os.getenv("FEEDER_ACTIVE_TIMEOUT", "600"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("feeder")

conf.verb = 0  # suppress scapy output

# --- Flow table ---
flows = {}      # key -> FlowState
flows_lock = threading.Lock()


def _stddev(vals, mean):
    if len(vals) < 2:
        return 0.0
    return math.sqrt(sum((v - mean) ** 2 for v in vals) / len(vals))


class FlowState:
    __slots__ = (
        "key", "first_ts", "last_ts",
        "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
        "fwd_sizes", "bwd_sizes",
        "fwd_ts", "bwd_ts",
        "all_sizes", "all_ts",
        "tcp_flags",
        "protocol", "dst_port",
    )

    def __init__(self, key, ts, size, direction, protocol, dst_port, flags):
        self.key = key
        self.first_ts = ts
        self.last_ts = ts
        self.protocol = protocol
        self.dst_port = dst_port
        self.tcp_flags = defaultdict(int)
        self.fwd_pkts = 0; self.bwd_pkts = 0
        self.fwd_bytes = 0; self.bwd_bytes = 0
        self.fwd_sizes = []; self.bwd_sizes = []
        self.fwd_ts = []; self.bwd_ts = []
        self.all_sizes = []; self.all_ts = [ts]
        self._add(ts, size, direction, flags)

    def _add(self, ts, size, direction, flags):
        self.last_ts = ts
        self.all_sizes.append(size)
        self.all_ts.append(ts)
        if direction == 0:
            self.fwd_pkts += 1; self.fwd_bytes += size
            self.fwd_sizes.append(size); self.fwd_ts.append(ts)
        else:
            self.bwd_pkts += 1; self.bwd_bytes += size
            self.bwd_sizes.append(size); self.bwd_ts.append(ts)
        for flag, bit in [("F",0x01),("S",0x02),("R",0x04),("P",0x08),
                          ("A",0x10),("U",0x20),("E",0x40),("C",0x80)]:
            if flags & bit:
                self.tcp_flags[flag] += 1

    def update(self, ts, size, direction, flags):
        self._add(ts, size, direction, flags)

    def _iats(self, ts_list):
        if len(ts_list) < 2:
            return []
        return [(ts_list[i] - ts_list[i-1]) * 1e6 for i in range(1, len(ts_list))]

    def to_features(self):
        dur_us = (self.last_ts - self.first_ts) * 1e6
        dur_s  = dur_us / 1e6 if dur_us > 0 else 1e-6

        fs = self.fwd_sizes or [0]
        bs = self.bwd_sizes or [0]
        as_ = self.all_sizes or [0]

        fwd_mean = sum(fs) / len(fs)
        bwd_mean = sum(bs) / len(bs)
        all_mean = sum(as_) / len(as_)

        fwd_iats = self._iats(self.fwd_ts)
        bwd_iats = self._iats(self.bwd_ts)
        all_iats = self._iats(self.all_ts)

        def stats(lst):
            if not lst:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            mn = min(lst); mx = max(lst)
            m = sum(lst) / len(lst)
            sd = _stddev(lst, m)
            tot = sum(lst)
            return mn, mx, m, sd, tot

        fi_mn, fi_mx, fi_m, fi_sd, fi_tot = stats(fwd_iats)
        bi_mn, bi_mx, bi_m, bi_sd, bi_tot = stats(bwd_iats)
        ai_mn, ai_mx, ai_m, ai_sd, _      = stats(all_iats)

        all_std = _stddev(as_, all_mean)

        return [
            self.dst_port,                                              # 0
            dur_us,                                                     # 1
            self.fwd_pkts,                                              # 2
            self.bwd_pkts,                                              # 3
            self.fwd_bytes,                                             # 4
            self.bwd_bytes,                                             # 5
            max(fs), min(fs), fwd_mean, _stddev(fs, fwd_mean),         # 6-9
            max(bs), min(bs), bwd_mean, _stddev(bs, bwd_mean),         # 10-13
            (self.fwd_bytes + self.bwd_bytes) / dur_s,                 # 14 flow bytes/s
            (self.fwd_pkts + self.bwd_pkts) / dur_s,                   # 15 flow pkts/s
            ai_m, ai_sd, ai_mx, ai_mn,                                 # 16-19 flow IAT
            fi_tot, fi_m, fi_sd, fi_mx, fi_mn,                        # 20-24 fwd IAT
            bi_tot, bi_m, bi_sd, bi_mx, bi_mn,                        # 25-29 bwd IAT
            self.tcp_flags["P"] if self.fwd_pkts else 0,               # 30 fwd PSH
            self.tcp_flags["P"] if self.bwd_pkts else 0,               # 31 bwd PSH
            self.tcp_flags["U"] if self.fwd_pkts else 0,               # 32 fwd URG
            self.tcp_flags["U"] if self.bwd_pkts else 0,               # 33 bwd URG
            0, 0,                                                       # 34-35 header len
            self.fwd_pkts / dur_s,                                      # 36 fwd pkts/s
            self.bwd_pkts / dur_s,                                      # 37 bwd pkts/s
            min(as_), max(as_), all_mean, all_std, all_std ** 2,       # 38-42 pkt len stats
            self.tcp_flags["F"],                                        # 43 FIN
            self.tcp_flags["S"],                                        # 44 SYN
            self.tcp_flags["R"],                                        # 45 RST
            self.tcp_flags["P"],                                        # 46 PSH
            self.tcp_flags["A"],                                        # 47 ACK
            self.tcp_flags["U"],                                        # 48 URG
            self.tcp_flags["C"],                                        # 49 CWE/CWR
            self.tcp_flags["E"],                                        # 50 ECE
            self.bwd_pkts / self.fwd_pkts if self.fwd_pkts else 0,     # 51 down/up ratio
            all_mean, fwd_mean, bwd_mean,                               # 52-54 avg sizes
            0,                                                          # 55 fwd header.1
            0, 0, 0, 0, 0, 0,                                          # 56-61 bulk stats
            self.fwd_pkts, self.fwd_bytes,                              # 62-63 subflow fwd
            self.bwd_pkts, self.bwd_bytes,                              # 64-65 subflow bwd
            0, 0,                                                       # 66-67 init win
            self.fwd_pkts,                                              # 68 act_data_pkt_fwd
            min(fs),                                                    # 69 min_seg_fwd
            0, 0, 0, 0,                                                 # 70-73 active
            0, 0, 0, 0,                                                 # 74-77 idle
        ]


def get_flow_key(pkt):
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = pkt[IP].proto
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        proto = pkt[IPv6].nh
    else:
        return None, None, None, None
    sport = dport = 0
    flags = 0
    if TCP in pkt:
        sport, dport, flags = pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    # canonical key: lower IP first
    if src <= dst:
        return (src, dst, sport, dport, proto), 0, dport, flags
    else:
        return (dst, src, dport, sport, proto), 1, sport, flags


def post_flow(flow):
    try:
        features = [float(x) for x in flow.to_features()]
        resp = requests.post(INFER_URL, json={"features": features}, timeout=1)
        r = resp.json()
        src_ip, dst_ip, sp, dp, proto = flow.key
        log.info(f"{src_ip}:{sp} -> {dst_ip}:{dp} proto={proto} "
                 f"pkts={flow.fwd_pkts+flow.bwd_pkts} "
                 f"pred={r.get('prediction')} conf={r.get('confidence',0):.3f}")
    except Exception as e:
        log.warning(f"inference error: {e}")


def expire_flows():
    """Background thread: expire idle/active flows and post them."""
    while True:
        now = time.time()
        to_expire = []
        with flows_lock:
            for key, flow in list(flows.items()):
                if (now - flow.last_ts > IDLE_TO or
                        now - flow.first_ts > ACTIVE_TO):
                    to_expire.append(flows.pop(key))
        for flow in to_expire:
            post_flow(flow)
        time.sleep(1)


def packet_callback(pkt):
    key, direction, dport, flags = get_flow_key(pkt)
    if key is None:
        return
    ts = float(pkt.time)
    size = len(pkt)
    proto = key[4]
    with flows_lock:
        if key in flows:
            flows[key].update(ts, size, direction, flags)
        else:
            flows[key] = FlowState(key, ts, size, direction, proto, dport, flags)


def main():
    log.info(f"Starting feeder on {INTERFACE} -> {INFER_URL}")
    t = threading.Thread(target=expire_flows, daemon=True)
    t.start()
    sniff(iface=INTERFACE, prn=packet_callback, store=False, promisc=True)


if __name__ == "__main__":
    main()
