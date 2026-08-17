#!/usr/bin/env bash

echo "============================================================"
echo "  🕶️ SHADOW NETWORK ANALYZER — STARTUP LAUNCHER"
echo "============================================================"
echo ""

# Check python3
if ! command -v python3 &> /dev/null; then
    echo "❌ [ERROR] Python 3 is not installed or not in PATH."
    exit 1
fi

# Create virtual environment if missing
if [ ! -d "venv" ]; then
    echo "📦 [INFO] Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate venv and install dependencies
echo "⚡ [INFO] Activating virtual environment & installing dependencies..."
source venv/bin/activate
pip install -q -r requirements.txt

# macOS / Linux BPF permissions notice
if [[ "$OSTYPE" == "darwin"* ]]; then
    if [ ! -w "/dev/bpf0" ]; then
        echo "💡 [MAC OS NOTE] Non-root capture requires permission to /dev/bpf*"
        echo "   Running permission helper script (sudo chmod 666 /dev/bpf*)..."
        sudo ./fix_mac_permissions.sh || true
    fi
fi

echo ""
echo "🚀 Starting Shadow Network Analyzer dashboard at http://127.0.0.1:5000"
echo "Press Ctrl+C to exit."
echo "============================================================"
echo ""

# Open browser if possible
if command -v open &> /dev/null; then
    open http://127.0.0.1:5000 &
elif command -v xdg-open &> /dev/null; then
    xdg-open http://127.0.0.1:5000 &
fi

python app.py
