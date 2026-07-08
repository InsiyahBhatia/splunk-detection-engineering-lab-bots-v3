#!/bin/bash
# Tool installation script for Detection Engineering Lab
# Installs YARA and Snort 3 on Ubuntu/Debian-based systems
# Usage: ./setup.sh [--skip-snort]

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${RED}[!]${NC} $1"; }

# --- YARA ---
install_yara() {
    if command -v yara &>/dev/null; then
        log "YARA already installed: $(yara --version)"
    else
        log "Installing YARA..."
        sudo apt update && sudo apt install -y yara
        log "YARA installed: $(yara --version)"
    fi
}

# --- Snort 3 ---
install_snort() {
    if command -v snort &>/dev/null; then
        log "Snort already installed: $(snort -V 2>&1 | head -1)"
        return
    fi

    log "Installing Snort 3 dependencies..."
    sudo apt install -y build-essential cmake flex g++ libhwloc-dev \
        libluajit-5.1-dev libssl-dev libpcap-dev libpcre2-dev \
        pkg-config zlib1g-dev libdumbnet-dev liblzma-dev

    log "Building LibDAQ..."
    cd /tmp
    git clone https://github.com/snort3/libdaq.git --depth 1 --branch v3.0.27
    cd libdaq
    ./bootstrap && ./configure --quiet && make -j$(nproc) && sudo make install
    sudo ldconfig

    log "Building Snort 3..."
    cd /tmp
    git clone https://github.com/snort3/snort3.git --depth 1
    cd snort3
    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local
    cmake --build build -j$(nproc) && sudo cmake --install build
    sudo ldconfig

    log "Snort installed: $(snort -V 2>&1 | head -1)"
}

# --- Scapy (for PCAP generation) ---
install_scapy() {
    log "Installing Scapy..."
    sudo apt install -y python3-scapy
    log "Scapy installed."
}

# --- Main ---
log "Starting tool installation..."

install_yara

if [ "${1:-}" != "--skip-snort" ]; then
    install_snort
else
    warn "Skipping Snort 3 installation (--skip-snort flag detected)"
fi

install_scapy

log "All tools installed successfully!"
