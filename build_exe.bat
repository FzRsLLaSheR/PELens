@echo off
setlocal
rem Builds two standalone executables (Python 3.10+ is needed only on the build machine):
rem   dist\pelens.exe      command line
rem   dist\pelens-gui.exe  graphical interface
rem A specific Python can be chosen with:  set PELENS_PYTHON=C:\path\to\python.exe
cd /d "%~dp0"
set "CHECK=import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)"
set "VPY=.venv\Scripts\python.exe"

rem an old .venv made with a Python that was removed or is too old: recreate it
if not exist .venv goto :find_python
"%VPY%" -c "%CHECK%" >nul 2>&1
if not errorlevel 1 goto :install
echo The existing .venv is broken or uses an old Python: recreating it.
rmdir /s /q .venv

:find_python
rem "python" is often an old version (e.g. Python 2.7 on FLARE-VM): try the py launcher first
set "PY="
if defined PELENS_PYTHON call :try "%PELENS_PYTHON%"
for %%v in (3.13 3.12 3.11 3.10 3) do if not defined PY call :try py -%%v
if not defined PY call :try python3
if not defined PY call :try python
if not defined PY (
    echo No Python 3.10 or newer found. Install Python 3.12 or 3.13 from python.org
    echo or set PELENS_PYTHON to the full path of python.exe.
    goto :fail
)
echo Using: %PY%
%PY% -m venv .venv
if errorlevel 1 goto :fail

:install
"%VPY%" -m pip install --quiet --upgrade pip
"%VPY%" -m pip install --quiet ".[gui]" pyinstaller
if errorlevel 1 goto :fail

"%VPY%" -m PyInstaller --noconfirm --onefile --console --name pelens --icon assets\pelens.ico --collect-data pelens --collect-all capstone --hidden-import dnfile --hidden-import yara --collect-data mscerts --exclude-module PySide6 --exclude-module numpy --exclude-module PIL --exclude-module tkinter --exclude-module ssl --exclude-module _ssl --exclude-module _hashlib --exclude-module pygments --exclude-module markdown_it --exclude-module chardet --exclude-module asyncio --exclude-module multiprocessing --exclude-module unittest --exclude-module sqlite3 --exclude-module cffi --exclude-module cryptography run_pelens.py
if errorlevel 1 goto :fail

rem the GUI uses a spec file: it leaves out the parts of Qt PELens does not use (smaller exe)
"%VPY%" -m PyInstaller --noconfirm pelens-gui.spec
if errorlevel 1 goto :fail

echo.
echo Done: dist\pelens.exe and dist\pelens-gui.exe
if not defined CI pause
exit /b 0

:try
rem %* = command that starts a Python; it is kept if it is 3.10 or newer
%* -c "%CHECK%" >nul 2>&1
if not errorlevel 1 set "PY=%*"
exit /b 0

:fail
echo.
echo Build failed, see the messages above.
if not defined CI pause
exit /b 1
