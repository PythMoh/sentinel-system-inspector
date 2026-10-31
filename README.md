# Sentinel: System Inspection Utility

Sentinel is a developer-focused diagnostics tool with two front ends: a **Typer + Rich command-line interface** and a **Flet desktop dashboard**. It inspects listening network ports and running processes with `psutil`, can free blocked ports, and sends error logs plus live system telemetry to an LLM (via the Groq API) to get a root-cause analysis and a fix command.

## Features
- **Port and process scan:** lists listening TCP/UDP sockets with the owning PID and process name, with optional port filter and process-name search.
- **Safe process termination:** frees a port or PID with a confirmation prompt, graceful terminate by default and optional force-kill.
- **Privilege handling:** detects whether it is running elevated and offers to relaunch with administrator rights when access is denied (Windows/PowerShell).
- **AI diagnostics:** `analyze` combines a pasted error log with local telemetry and asks Groq for root cause, remediation steps and a terminal command. It tries several models in order (`llama-3.3-70b-versatile`, `llama-3.1-8b-instant`, `openai/gpt-oss-20b`) and falls back if one is unavailable.
- **Desktop dashboard (Flet):** a "Command Center" window with a live port table and an AI diagnostic panel.

## Tech stack
Python · Typer · Rich · psutil · Flet · Groq API

## Setup
```bash
git clone https://github.com/<your-username>/sentinel-system-inspector.git
cd sentinel-system-inspector
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # then add your Groq API key
```
Get a free API key at https://console.groq.com/keys. The scan and kill commands work without a key. Only `analyze` and the AI panel need it.

## Usage
**Command line**
```bash
python sentinel.py scan                    # all listening ports
python sentinel.py scan --port 8080        # one port
python sentinel.py scan --name python      # also list processes matching "python"
python sentinel.py kill --port 8080        # free a port (asks for confirmation)
python sentinel.py kill --pid 1234 --force # force-kill a PID
python sentinel.py analyze "ModuleNotFoundError: No module named 'foo'" --port 8000
```
**Desktop dashboard**
```bash
python sentinel_flet.py
```

## Notes
- Some sockets and system processes need administrator/root rights to inspect or stop. Without them Sentinel shows a warning instead of failing.
- The privilege relaunch helper uses PowerShell, so it only works on Windows. Scanning and killing work on Windows, Linux and macOS.
- Be careful with `kill`. It stops real processes. Sentinel always asks for confirmation first.
