@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.10 or newer and enable Add Python to PATH.
  pause
  exit /b 1
)
python --version
python backend\server.py
if errorlevel 1 (
  echo SENTINEL-X exited with an error. Read the message above.
  pause
)
endlocal
