@echo off
rem ============================================================
rem  PLC Discovery（GUI）を起動します。ダブルクリックで実行してください。
rem  初回は仮想環境の作成とパッケージのインストールを行います。
rem ============================================================
setlocal
cd /d "%~dp0"

call "%~dp0scripts\setup_env.bat"
if errorlevel 1 goto :error

"%VENV_PY%" -c "import tkinter" >nul 2>&1
if errorlevel 1 goto :no_tk

rem 画面を開く前に読み込みエラーがないか確認する（エラーはこのウィンドウに表示）
"%VENV_PY%" -c "import plc_gui"
if errorlevel 1 goto :error

start "" "%VENV_PYW%" "%~dp0plc_gui.py"
exit /b 0

:no_tk
echo [エラー] この Python には Tkinter（画面表示の部品）が含まれていません。
echo   python.org のインストーラーで「tcl/tk and IDLE」を有効にして再インストールしてください。

:error
echo.
pause
exit /b 1
