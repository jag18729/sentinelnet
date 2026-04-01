# Suricata IDS Configuration (RV2)

Suricata 7.0.3 running on Orange Pi RV2 with AF_PACKET on `end0` (PA-220 dmz-security zone).

## Deployment

```bash
# Install (already installed on RV2)
sudo apt install suricata suricata-update

# Copy config
sudo cp suricata.yaml /etc/suricata/suricata.yaml

# Update rules
sudo suricata-update
sudo systemctl restart suricata
```

## Configuration Highlights

| Setting | Value |
|---------|-------|
| Interface | `end0` (AF_PACKET) |
| Cluster ID | 99 |
| HOME_NET | `192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12` |
| Rules | 74,999 (ET Open + community, `/var/lib/suricata/rules/`) |
| EVE log | `/var/log/suricata/eve.json` |

## Architecture Note

Suricata monitors `end0` (PA-220 zone traffic). The SentinelNet feeder monitors `end1` (SPAN mirror of full LAN uplink). These are complementary:

- **Suricata** = signature-based detection (74K rules, known threats)
- **SentinelNet feeder** = ML-based classification (behavioral, unknown threats)

## Rule Updates

```bash
sudo suricata-update
sudo suricata-update list-sources
sudo systemctl reload suricata
```
