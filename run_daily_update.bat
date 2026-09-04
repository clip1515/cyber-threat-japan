@echo off
REM ============================================================
REM cyber-threat-japan 日次自動実行用バッチファイル (Windows)
REM Windowsタスクスケジューラの「操作」でこのファイルを指定してください。
REM 詳細な登録手順は README.md の
REM 「毎日の自動実行(Windows タスクスケジューラ)」を参照してください。
REM ============================================================

REM このバッチファイル自身がある場所(=プロジェクトのルート)に移動する。
cd /d "%~dp0"

REM 仮想環境を作っている場合は以下のコメントを外して有効化してください。
REM call .venv\Scripts\activate.bat

REM 収集→解析→保存→daily_report.md生成までを1回実行する。
python update.py >> logs\scheduled_task.log 2>&1

REM 終了コードをそのままタスクスケジューラに返す。
exit /b %ERRORLEVEL%