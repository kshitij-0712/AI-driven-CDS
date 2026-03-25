@echo off
REM AdaptiveShield Demo Runner for Windows
REM Run this script from the project root directory

echo ============================================================
echo    AdaptiveShield - Capstone Phase 2 Demo
echo ============================================================
echo.

REM Check if venv exists
if not exist ".venv\Scripts\activate.bat" (
    echo ERROR: Virtual environment not found at .venv\
    echo Please create it with: python -m venv .venv
    echo Then install dependencies: pip install torch pandas scikit-learn numpy pyyaml
    exit /b 1
)

REM Activate venv and run demo
echo Activating virtual environment...
call .venv\Scripts\activate.bat

REM Set PYTHONPATH
set PYTHONPATH=src

echo Running demo...
echo.

python src\demo.py %*

echo.
echo Demo completed.
pause
