# Detection Rules - Test Guide

## 1. Install Tools

### YARA
```bash
sudo apt update && sudo apt install -y yara
yara --version
```

### Snort 3 (source build - Ubuntu 26.04+)
```bash
# Dependencies
sudo apt install -y build-essential cmake flex g++ libhwloc-dev \
  libluajit-5.1-dev libssl-dev libpcap-dev libpcre2-dev \
  pkg-config zlib1g-dev libdumbnet-dev liblzma-dev

# LibDAQ
cd /tmp
git clone https://github.com/snort3/libdaq.git --depth 1 --branch v3.0.27
cd libdaq
./bootstrap && ./configure --quiet && make -j$(nproc) && sudo make install
sudo ldconfig

# Snort 3
cd /tmp
git clone https://github.com/snort3/snort3.git --depth 1
cd snort3
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build -j$(nproc) && sudo cmake --install build
sudo ldconfig
snort -V
```

## 2. Configure Snort

Create `~/snort-config/snort.lua` (or copy from `05-Snort/snort.lua`):
```lua
HOME_NET = '192.168.0.0/16'
EXTERNAL_NET = '!$HOME_NET'

ips =
{
    rules = [[
        include /path/to/05-Snort/snort-c2-port9998.rules
    ]]
}
```

Validate:
```bash
snort -c ~/snort-config/snort.lua --warn-all
```

## 3. Test YARA Rules

```bash
cd scripts
chmod +x test-yara.sh
./test-yara.sh
```

Expected results:

| Sample | Rules Matching |
|--------|----------------|
| `coinhive-test.js` | Coinhive_JS_Miner_Generic |
| `coinhive-test-ws.js` | Coinhive_JS_Miner_Generic |
| `coinhive-injected.html` | Coinhive_JS_Miner_Generic + Coinhive_JS_Miner_Injected_In_HTML |
| `generic-miner.js` | Generic_Browser_Cryptominer_Behavior |
| `benign.js` | (none) |
| `normal.html` | (none) |

## 4. Generate Test PCAP & Run Snort

```bash
# Install Scapy
sudo apt install -y python3-scapy

# Generate synthetic C2 traffic
python3 << 'EOF'
from scapy.all import *
pkts = []
pkts.append(IP(src="192.168.1.100",dst="34.215.24.225")/TCP(sport=44444,dport=9998,flags="PA")/Raw(b"A"*60))
pkts.append(IP(src="34.215.24.225",dst="192.168.1.100")/TCP(sport=9998,dport=44444,flags="PA")/Raw(b"B"*60))
pkts.append(IP(src="34.215.24.225",dst="192.168.1.100")/TCP(sport=9998,dport=44445,flags="PA")/Raw(b"C"*1500))
wrpcap("/tmp/c2-test.pcap", pkts)
print("PCAP created")
EOF

# Run Snort
mkdir -p /tmp/snort-output
snort -c ~/snort-config/snort.lua -r /tmp/c2-test.pcap -A alert_fast -l /tmp/snort-output
cat /tmp/snort-output/alert_fast.txt
```

Expected alerts:
- `Outbound C2 beacon`
- `Inbound C2 response`

## File Reference

| File | Tool | Purpose |
|------|------|---------|
| `04-YARA/yara-coinhive-miner.yar` | YARA | Browser cryptominer detection (3 rules) |
| `05-Snort/snort-c2-port9998.rules` | Snort 3 | C2 beacon + payload delivery (4 rules) |
| `13-Detection-Pack/scripts/test-yara.sh` | - | Automated YARA test runner |
| `13-Detection-Pack/scripts/setup.sh` | - | Tool installation script |
| `13-Detection-Pack/test-samples/coinhive-test.js` | - | YARA test: JS miner with CoinHive.Anonymous |
| `13-Detection-Pack/test-samples/coinhive-test-ws.js` | - | YARA test: WebSocket + CoinHive API |
| `13-Detection-Pack/test-samples/coinhive-injected.html` | - | YARA test: miner injected in HTML |
| `13-Detection-Pack/test-samples/generic-miner.js` | - | YARA test: generic miner behavior |
| `13-Detection-Pack/test-samples/benign.js` | - | Negative test: clean JS |
| `13-Detection-Pack/test-samples/normal.html` | - | Negative test: clean HTML |
