@echo off
TITLE Shadow Network Analyzer Launcher
echo ============================================================
echo   🕶️ SHADOW NETWORK ANALYZER &mdash; STARTUP LAUNCHER
echo ============================================================
echo.

:: Check if Python is installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not added to PATH.
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)

:: Create Virtual Environment if missing
if not exist "venv" (
    echo [INFO] Creating Python virtual environment (venv)...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: Activate Virtual Environment & Install Dependencies
echo [INFO] Activating virtual environment and verifying dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r requirements.txt

echo.
echo [IMPORTANT WINDOWS NOTE]
echo Packet sniffing requires Npcap on Windows.
echo Download Npcap from: https://npcap.com/#download
echo (Select "Install Npcap in WinPcap API-compatible Mode" during setup)
echo.
echo Launching Web Dashboard at http://127.0.0.1:5000 ...
echo Press Ctrl+C in this terminal to stop the server.
echo ============================================================
echo.

:: Open Browser automatically after 2 seconds delay
start "" http://127.0.0.1:5000

:: Run Flask App
python app.py

pause
