@echo off
rem ============================================================
rem  PLC Discovery 実行環境のセットアップ
rem  （start_gui.bat / plc_scanner.bat から呼び出されます）
rem
rem   1. Python 3.10 以降を探す（py ランチャー → python の順）
rem   2. 初回のみ .venv（仮想環境）を作成する
rem   3. requirements.txt が変わったときだけパッケージをインストールする
rem
rem  成功すると VENV_PY / VENV_PYW を設定し、終了コード 0 で戻ります。
rem ============================================================
setlocal EnableExtensions
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "VENV=%ROOT%\.venv"
set "VPY=%VENV%\Scripts\python.exe"
set "VPYW=%VENV%\Scripts\pythonw.exe"
set "STAMP=%VENV%\requirements.installed"

if exist "%VPY%" goto :check_packages

rem --- Python 3.10 以降を探す ---
set "BASE_PY="
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 set "BASE_PY=py -3"
if defined BASE_PY goto :create_venv
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 set "BASE_PY=python"
if defined BASE_PY goto :create_venv
echo [エラー] Python 3.10 以降が見つかりません。
echo   https://www.python.org/downloads/ からインストールしてください。
echo   インストール時に「Add python.exe to PATH」にチェックを入れてください。
exit /b 1

:create_venv
echo 初回セットアップ: 仮想環境を作成しています...
%BASE_PY% -m venv "%VENV%"
if errorlevel 1 goto :venv_failed

:check_packages
rem requirements.txt がインストール済みのものと同じなら何もしない
fc /b "%ROOT%\requirements.txt" "%STAMP%" >nul 2>&1
if not errorlevel 1 goto :done
echo 依存パッケージをインストールしています。数分かかることがあります...
"%VPY%" -m pip install --disable-pip-version-check -q --upgrade pip >nul 2>&1
"%VPY%" -m pip install --disable-pip-version-check -r "%ROOT%\requirements.txt"
if errorlevel 1 goto :pip_failed
echo 任意パッケージのインストールを試しています...
"%VPY%" -m pip install --disable-pip-version-check -q -r "%ROOT%\requirements-optional.txt" >nul 2>&1
if errorlevel 1 echo   ※ netifaces は入りませんでした。サブネットを /24 とみなして探索します。動作に支障はありません。
copy /y "%ROOT%\requirements.txt" "%STAMP%" >nul
echo セットアップが完了しました。

:done
endlocal & set "VENV_PY=%VPY%" & set "VENV_PYW=%VPYW%"
exit /b 0

:venv_failed
echo [エラー] 仮想環境の作成に失敗しました。
exit /b 1

:pip_failed
rem 以前のインストールは成功している: 起動できなくするより、入っているパッケージで動かす
if not exist "%STAMP%" goto :pip_failed_first
echo [警告] パッケージを更新できませんでした。以前にインストールしたパッケージで起動します。
echo   インターネットに接続できるときに、もう一度起動すると更新されます。
goto :done

:pip_failed_first
echo [エラー] パッケージのインストールに失敗しました。
echo   インターネット接続やプロキシの設定を確認してから、もう一度実行してください。
exit /b 1
