#!/bin/bash
# Shadow Network Analyzer - macOS BPF Permission Fixer
# Grants read/write permissions to /dev/bpf* devices for raw packet sniffing

echo "============================================================"
echo " 🕶️ Shadow Network Analyzer - macOS BPF Permission Fixer"
echo "============================================================"
echo ""
echo "Granting read/write permissions to /dev/bpf* devices..."

sudo chmod 666 /dev/bpf*

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ SUCCESS! /dev/bpf* permissions updated."
    echo "You can now run packet captures without needing sudo every time."
    echo "============================================================"
else
    echo ""
    echo "❌ Failed to update permissions. Please run manually: sudo chmod 666 /dev/bpf*"
    echo "============================================================"
fi
