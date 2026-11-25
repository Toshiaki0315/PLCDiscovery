@echo off
rem Run the CI checks (lint, unit and integration tests) on this machine.
rem Uses .venv when the development tools are installed there (requirements-dev.txt;
rem the launchers create it with the runtime packages only), otherwise py / python.
rem Options: --lint, --no-integration
cd /d "%~dp0.."
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import black, pytest" >nul 2>nul && goto venv
)
rem Not "where py && (py ...) || (python ...)": that runs the checks a second
rem time with python whenever the first run fails (a check failed).
where py >nul 2>nul || goto nopy
py -3 scripts\check.py %*
exit /b %ERRORLEVEL%
:nopy
python scripts\check.py %*
exit /b %ERRORLEVEL%
:venv
".venv\Scripts\python.exe" scripts\check.py %*
exit /b %ERRORLEVEL%
