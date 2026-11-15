@echo off
rem ============================================================
rem  PLC Scanner（コマンドライン版）
rem
rem  使い方の例:
rem    plc_scanner.bat --mode discover --ip-range 192.168.1.0/24
rem    plc_scanner.bat --mode range --target 192.168.1.10 --device D --range 0-99
rem
rem  引数なしで実行（ダブルクリック）するとヘルプを表示します。
rem  誤ってネットワーク探索を始めないためです。
rem ============================================================
setlocal

call "%~dp0scripts\setup_env.bat"
if errorlevel 1 goto :error

if "%~1"=="" goto :help

"%VENV_PY%" "%~dp0plc_scanner.py" %*
exit /b %errorlevel%

:help
"%VENV_PY%" "%~dp0plc_scanner.py" --help
echo.
pause
exit /b 0

:error
pause
exit /b 1
