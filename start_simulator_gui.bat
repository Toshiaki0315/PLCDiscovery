@echo off
rem ============================================================
rem  PLC シミュレータの GUI を起動します（ダブルクリックで実行できます）。
rem  シミュレータの起動・停止、スキャナーが読む値の書き換え・自動変化、ログの確認ができます。
rem
rem  待ち受けアドレスは 127.0.0.1（このPCからのみ接続可）です。画面で変更できます。
rem  ※工場のネットワーク上では、本物のPLCと紛らわしいため 0.0.0.0 にしないでください。
rem  標準ライブラリ（Tkinter を含む）だけで動くため、パッケージのインストールは不要です。
rem ============================================================
setlocal EnableExtensions

rem --- Python を決める（.venv があればそれを使う。画面なしで起動するため pythonw を優先） ---
set "PY=%~dp0.venv\Scripts\pythonw.exe"
if exist "%PY%" "%~dp0.venv\Scripts\python.exe" -c "import tkinter" >nul 2>&1
if exist "%PY%" if not errorlevel 1 goto :run
set "PY="
py -3 -c "import sys, tkinter; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto :run
python -c "import sys, tkinter; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto :run
echo [エラー] Tkinter を含む Python 3.10 以降が見つかりません。
echo   https://www.python.org/downloads/ からインストールしてください（tcl/tk を含めてください）。
pause
exit /b 1

:run
if "%PY%"=="py -3" (
    start "" pyw -3 "%~dp0simulators\simulator_gui.py" %*
) else if "%PY%"=="python" (
    start "" pythonw "%~dp0simulators\simulator_gui.py" %*
) else (
    start "" "%PY%" "%~dp0simulators\simulator_gui.py" %*
)
exit /b 0
