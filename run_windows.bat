@echo off
setlocal
cd /d "%~dp0"
if not exist .venv (
  py -m venv .venv
)
call .venv\Scripts\activate
pip install -r requirements.txt
if not exist .env copy .env.example .env
set FLASK_APP=app.py
set FLASK_DEBUG=1
flask run --debug --host=127.0.0.1 --port=5000
