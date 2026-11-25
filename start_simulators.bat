@echo off
rem ============================================================
rem  PLC シミュレータ（SLMP / Modbus / EtherNet/IP / S7 / FINS）を起動します。
rem  ダブルクリックで実行できます。止めるときは Ctrl+C を押してください。
rem
rem  待ち受けアドレスは 127.0.0.1（このPCからのみ接続可）です。
rem  他のPCから接続したい場合: start_simulators.bat --host 0.0.0.0
rem  ※工場のネットワーク上では、本物のPLCと紛らわしいため 0.0.0.0 にしないでください。
rem
rem  ポート: SLMP 5001 / Modbus 1502 / EtherNet/IP 44818（SLC形式）・44819（Logix形式）・44820（オムロン NJ/NX 形式） / S7 1102 / FINS 9600(UDP,TCP)
rem  シミュレータは標準ライブラリだけで動くため、パッケージのインストールは不要です。
rem ============================================================
setlocal EnableExtensions

rem --- Python を決める（.venv があればそれを使う） ---
set "PY=%~dp0.venv\Scripts\python.exe"
if exist "%PY%" goto :run
set "PY="
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto :run
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto :run
echo [エラー] Python 3.10 以降が見つかりません。
echo   https://www.python.org/downloads/ からインストールしてください。
goto :error

:run
echo シミュレータを起動しています。止めるときは Ctrl+C を押してください。
echo.
if "%PY%"=="py -3" (
    py -3 "%~dp0simulators\run_all.py" --host 127.0.0.1 %*
) else (
    "%PY%" "%~dp0simulators\run_all.py" --host 127.0.0.1 %*
)
if errorlevel 1 goto :error
exit /b 0

:error
echo.
echo シミュレータの起動に失敗しました。ポートが他のプログラムで使われていないか確認してください。
pause
exit /b 1
