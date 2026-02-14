# SentinelNet Deployment Architecture

> *It pays to know infrastructure. Half of ML research dies on the whiteboard because nobody can deploy it. The other half dies in a Jupyter notebook because nobody built the pipeline. This one runs on bare metal, behind a real firewall, classifying real traffic.*

## Overview

SentinelNet operates as a distributed intrusion detection system combining signature-based detection (Suricata) with ML-powered flow classification (PyTorch/ONNX). The system is deployed on a physically microsegmented home lab network, where each compute node occupies its own DMZ zone behind a Palo Alto PA-220 next-generation firewall.

This architecture is not simulated. Every packet traverses real firewall policy. Every alert is generated from live network telemetry. The ML pipeline classifies production traffic in real time.

## Network Architecture

```
                    Internet
                       │
                   ┌───┴───┐
                   │  UDM   │  (core router, 192.168.2.1)
                   └───┬───┘
                       │ 192.168.2.0/24
                       │
                ┌──────┴──────┐
                │   PA-220    │  reveal-fw
                │  (PAN-OS    │  Physical microsegmentation
                │   10.2.10)  │  9 security policies
                └──┬───┬───┬──┘  3 NAT rules
                   │   │   │     Per-zone traffic inspection
                   │   │   │
        ┌──────────┘   │   └──────────┐
        │              │              │
   eth1/1         eth1/8         eth1/2
   dmz-mgmt      dmz-services   dmz-security
   192.168.21.0/24  192.168.20.0/24  192.168.22.0/24
        │              │              │
   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐
   │   pi0   │   │   pi1   │   │   pi2   │
   │ (pending)│   │ Grafana │   │ Sentinel│
   │ DNS/LDAP│   │ Prom/Loki│  │ Suricata│
   └─────────┘   └─────────┘   └─────────┘
```

### Design Rationale: Physical vs. VLAN Segmentation

This deployment uses **physical port isolation** rather than 802.1Q VLANs. Each Raspberry Pi connects to a dedicated PA-220 data port with its own L3 interface and security zone. This is a deliberate architectural choice:

1. **No trunk misconfiguration risk.** VLAN hopping attacks (Q-in-Q, DTP exploitation) are eliminated at the physical layer.
2. **Per-device firewall policy.** Each Pi's traffic is independently inspectable. Inter-zone communication requires explicit security policy — there is no implicit trust between compute nodes.
3. **Failure isolation.** A compromised node cannot sniff adjacent traffic. The PA-220 enforces zone boundaries in hardware.
4. **Simplified audit trail.** Every inter-zone packet generates a traffic log entry on the PA-220, creating a complete forensic record without additional tooling.

In enterprise environments, VLANs are preferred for scale. At lab scale (3–5 nodes), physical segmentation provides stronger guarantees with less configuration complexity.

## Inference Pipeline

```
Suricata (AF_PACKET, host network)
    │
    ├── Packet capture on eth0
    ├── ET Open ruleset (42MB, full signature set)
    ├── Protocol detection: HTTP, TLS, DNS, SSH, SMB
    ├── JA3/JA4 fingerprinting
    └── EVE JSON output (/var/log/suricata/eve.json)
         │
    sentinelnet-bridge.service
         │
         ├── Tails EVE JSON in real time
         ├── Extracts flow/alert events
         ├── Maps Suricata flow stats → CICIDS2017 feature vector (78 features)
         │   ├── Phase 1 (current): ~20 features from EVE flow metadata
         │   └── Phase 2 (planned): Full 78 features via NFStream
         ├── Forwards feature vector to SentinelNet API
         └── Logs enriched events (classification + metadata)
              │
    sentinelnet.service (FastAPI + ONNX Runtime)
         │
         ├── ONNX model inference (15-class classifier)
         ├── Softmax probability distribution per flow
         ├── Prometheus metrics (/metrics endpoint)
         └── Batch prediction support (/predict/batch)
```

### Attack Classes (CICIDS2017)

| Class | Description |
|-------|-------------|
| BENIGN | Normal traffic |
| Bot | Botnet C2 communication |
| DDoS | Distributed denial of service |
| DoS GoldenEye | HTTP flood (GoldenEye tool) |
| DoS Hulk | HTTP flood (Hulk tool) |
| DoS Slowhttptest | Slow HTTP attack |
| DoS slowloris | Slowloris connection exhaustion |
| FTP-Patator | FTP brute force |
| Heartbleed | OpenSSL Heartbleed exploitation |
| Infiltration | Network infiltration / lateral movement |
| PortScan | Port scanning / reconnaissance |
| SSH-Patator | SSH brute force |
| Web Attack – Brute Force | HTTP authentication brute force |
| Web Attack – SQL Injection | SQL injection attempts |
| Web Attack – XSS | Cross-site scripting |

## Feature Engineering: Suricata → CICIDS2017 Mapping

The CICIDS2017 dataset defines 78 flow-level features extracted by CICFlowMeter. Suricata's EVE JSON provides a subset of these through its flow event type. The bridge performs a best-effort mapping:

**Directly mappable (~20 features):**
- Destination Port, Flow Duration
- Total Fwd/Bwd Packets, Total Fwd/Bwd Bytes
- Fwd/Bwd Packet Length Mean
- Flow Bytes/s, Flow Packets/s
- Fwd/Bwd Packets/s
- Down/Up Ratio, Average Packet Size
- Subflow Fwd/Bwd Packets and Bytes

**Requires packet-level analysis (~58 features):**
- Inter-arrival time statistics (IAT Mean/Std/Max/Min)
- Packet length distributions (Std, Variance, Min, Max)
- TCP flag counts (FIN, SYN, RST, PSH, ACK, URG, CWE, ECE)
- Header lengths, bulk transfer statistics
- Active/Idle time statistics
- Initial window sizes

**Phase 2 mitigation:** NFStream (Python library) performs per-packet feature extraction compatible with CICFlowMeter output format. Deploying NFStream alongside Suricata enables full 78-feature extraction without replacing the IDS pipeline.

## Services

| Service | Type | Port | Description |
|---------|------|------|-------------|
| sentinelnet.service | systemd | 8000 | ONNX inference API |
| sentinelnet-bridge.service | systemd | — | EVE → SentinelNet pipeline |
| suricata | Docker (host net) | — | IDS, packet capture |
| datadog-agent | Docker | 8126/8125 | APM + metrics |
| node-exporter | systemd | 9100 | Prometheus host metrics |

## Hardware

| Component | Specification |
|-----------|--------------|
| Board | Raspberry Pi 5 Model B Rev 1.1 |
| CPU | BCM2712, 4 cores @ 2.40 GHz (ARM Cortex-A76) |
| RAM | 16 GB LPDDR4X |
| Storage | Samsung PM9C1a 256GB NVMe (PCIe) |
| Network | 1 Gbps Ethernet (Broadcom bcmgenet) |
| OS | Debian 13 (trixie), Kernel 6.12 |

### Storage Performance (fio benchmarks, 2026-02-13)

| Test | Bandwidth | IOPS |
|------|-----------|------|
| Sequential Read (1M) | 3,988 MB/s | 3,988 |
| Sequential Write (1M) | 4,082 MB/s | 4,081 |
| Random 4K Read (4 jobs) | 3,755 MB/s | 962K |
| Random 4K Write (4 jobs) | 2,610 MB/s | 669K |

NVMe boot migration from SD card completed 2026-02-13. Boot firmware loads from SD, root filesystem on NVMe.

## Firewall Policy (PA-220 reveal-fw)

Pi2 resides in the `dmz-security` zone (192.168.22.0/24). Relevant policies:

| Rule | From | To | Action | Services |
|------|------|----|--------|----------|
| dmz-security-to-internet | dmz-security | untrust | allow | SSL, DNS, NTP, apt-get, web |
| mgmt-to-security-monitoring | dmz-mgmt | dmz-security | allow | HTTP, node_exporter, Loki |
| security-to-mgmt-logs | dmz-security | dmz-mgmt | allow | syslog, Loki |
| workstation-to-dmz | untrust (workstations) | dmz-security | allow | SSH, HTTP/S, ping |
| deny-interzone | any | any | deny | all (logged) |

All inter-zone traffic is logged. Default deny applies to any traffic not explicitly permitted.

## Future Work

### Phase 2: Full Feature Extraction
- Deploy NFStream for 78-feature CICIDS2017-compatible extraction
- Train improved model on XPS GPU (RTX 4060 Ti, CICIDS2017 dataset)
- Export quantized ONNX model, deploy to pi2

### Phase 3: Multi-Sensor Architecture
- Orange Pi RV2 (RISC-V) as edge IDS sensor on PA-220 SPAN port
- Heterogeneous architecture: ARM (Pi 5) + RISC-V (Orange Pi) + x86 (training)
- Edge ONNX pre-filtering with INT8 quantized binary classifier
- Centralized deep analysis on pi2 PyTorch pipeline

### Phase 4: Adversarial Robustness Research
- FGSM, PGD, C&W attacks against trained classifier
- Adversarial training with ε-bounded perturbations
- Feature-space vs. problem-space attack comparison
- Defense evaluation: adversarial training, input gradient regularization, ensemble methods

---

*Deployed: 2026-02-13 | Pi2 (dmz-security) behind PA-220 reveal-fw*
*Pipeline: Suricata 8.0.3 → SentinelNet Bridge v0.2 → ONNX Runtime (15-class)*
