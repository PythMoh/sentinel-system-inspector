#!/usr/bin/env python3
import os
import sys
import ctypes
import json
import subprocess
from typing import Optional, List, Dict, Any
import typer
import psutil
from dotenv import load_dotenv
from groq import Groq
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Automatically load environment variables from .env
load_dotenv()

app = typer.Typer(
    name="sentinel",
    help="Sentinel CLI — Local environment & diagnostic companion.",
    add_completion=False,
    no_args_is_help=True,  # Shows help menu when no subcommand is passed
)
console = Console()

def is_admin() -> bool:
    """Checks if the script is currently running with administrative/root privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return os.getuid() == 0

def relaunch_as_admin():
    """Relaunches the current script in an elevated PowerShell terminal window."""
    console.print("\n[bold yellow][!] Relaunching Sentinel with elevated privileges...[/bold yellow]")
    script_path = os.path.abspath(sys.argv[0])
    python_exe = sys.executable
    args = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    ps_command = f'Start-Process "{python_exe}" -ArgumentList \'"{script_path}" {args}\' -Verb RunAs'
    
    try:
        subprocess.run(["powershell", "-Command", ps_command], check=True)
    except Exception as e:
        console.print(f"[bold red]Failed to elevate process:[/bold red] {e}")

class EnvironmentInspector:
    """Core engine for inspecting system processes, network sockets, and file locks."""

    @staticmethod
    def get_listening_ports() -> List[Dict[str, Any]]:
        listening_sockets = []
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            console.print("[bold yellow][!] Warning:[/bold yellow] Access denied for some sockets.")
            connections = []

        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                pid = conn.pid
                process_name = "Unknown"
                if pid:
                    try:
                        proc = psutil.Process(pid)
                        process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = "[Access Denied/Ended]"

                listening_sockets.append({
                    "port": conn.laddr.port,
                    "ip": conn.laddr.ip,
                    "pid": pid or "N/A",
                    "process": process_name,
                    "protocol": "TCP" if conn.type == 1 else "UDP"
                })
        return sorted(listening_sockets, key=lambda x: x["port"])

    @staticmethod
    def get_process_locks(search_term: Optional[str] = None) -> List[Dict[str, Any]]:
        matching_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'status']):
            try:
                pinfo = proc.info
                name = pinfo['name'] or ""
                cmdline = " ".join(pinfo['cmdline'] or [])

                if search_term:
                    term = search_term.lower()
                    if term not in name.lower() and term not in cmdline.lower():
                        continue

                matching_processes.append({
                    "pid": pinfo['pid'],
                    "name": name,
                    "status": pinfo['status'],
                    "cmdline": cmdline[:60] + "..." if len(cmdline) > 60 else cmdline
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return matching_processes


# --- CLI Commands ---

@app.command()
def scan(
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Check a specific port (e.g., 3306, 8080)"),
    filter_name: Optional[str] = typer.Option(None, "--name", "-n", help="Filter running processes by name"),
):
    """Scan active network ports and inspect running process locks."""
    admin_status = "[bold green](Elevated)[/bold green]" if is_admin() else "[bold yellow](User Mode)[/bold yellow]"
    console.print(Panel.fit(f"[bold cyan]Sentinel System Scan[/bold cyan] {admin_status}", border_style="cyan"))

    ports = EnvironmentInspector.get_listening_ports()
    if port:
        ports = [p for p in ports if p["port"] == port]

    table = Table(title="Listening Ports & Bound Processes", header_style="bold magenta")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Proto", style="green")
    table.add_column("IP Address", style="white")
    table.add_column("PID", style="yellow", justify="right")
    table.add_column("Process Name", style="bold white")

    for p in ports:
        table.add_row(str(p["port"]), p["protocol"], p["ip"], str(p["pid"]), p["process"])

    console.print(table)

    if filter_name:
        console.print(f"\n[bold yellow]Searching for process locks matching '{filter_name}'...[/bold yellow]")
        locks = EnvironmentInspector.get_process_locks(search_term=filter_name)
        
        lock_table = Table(title=f"Active Process Locks: '{filter_name}'", header_style="bold yellow")
        lock_table.add_column("PID", style="cyan", justify="right")
        lock_table.add_column("Name", style="bold white")
        lock_table.add_column("Status", style="green")
        lock_table.add_column("Command Line", style="dim white")

        for l in locks:
            lock_table.add_row(str(l["pid"]), l["name"], l["status"], l["cmdline"])

        console.print(lock_table)


@app.command()
def kill(
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Target port to free up"),
    pid: Optional[int] = typer.Option(None, "--pid", help="Target PID to terminate"),
    force: bool = typer.Option(False, "--force", "-f", help="Force kill process (SIGKILL)")
):
    """Safely release bound ports or terminate hanging background processes."""
    target_pid = pid

    if port and not target_pid:
        ports = EnvironmentInspector.get_listening_ports()
        matches = [p for p in ports if p["port"] == port]
        if not matches:
            console.print(f"[bold red]No process found listening on port {port}.[/bold red]")
            raise typer.Exit(code=1)
        target_pid = matches[0]["pid"]

    if not target_pid or target_pid == "N/A":
        console.print("[bold red]Please specify a valid --port or --pid to terminate.[/bold red]")
        raise typer.Exit(code=1)

    try:
        proc = psutil.Process(target_pid)
        proc_name = proc.name()
        
        confirm = typer.confirm(f"Are you sure you want to terminate process '{proc_name}' (PID {target_pid})?")
        if not confirm:
            console.print("[yellow]Operation cancelled.[/yellow]")
            raise typer.Abort()

        if force:
            proc.kill()
            console.print(f"[bold green]Successfully force-killed PID {target_pid} ({proc_name}).[/bold green]")
        else:
            proc.terminate()
            console.print(f"[bold green]Sent termination signal to PID {target_pid} ({proc_name}).[/bold green]")

    except psutil.NoSuchProcess:
        console.print(f"[bold red]Process with PID {target_pid} no longer exists.[/bold red]")
    except psutil.AccessDenied:
        console.print(f"\n[bold red][!] Access Denied:[/bold red] PID {target_pid} is a protected system process.")
        
        if not is_admin():
            elevate_confirm = typer.confirm("[?] Would you like to rerun this command with Administrative privileges?")
            if elevate_confirm:
                relaunch_as_admin()
            else:
                console.print("[yellow]Operation aborted due to insufficient permissions.[/yellow]")


@app.command()
def analyze(
    log_text: str = typer.Argument(..., help="Paste the error log or issue description"),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Associated port to pass as context")
):
    """Analyzes terminal errors alongside local system telemetry using Groq."""
    console.print(Panel.fit("[bold cyan]Sentinel Groq AI Diagnostics[/bold cyan]", border_style="cyan"))

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        console.print("[bold red]Error:[/bold red] GROQ_API_KEY is missing!")
        console.print("[yellow]Create a .env file in your project folder with: GROQ_API_KEY=gsk_...[/yellow]")
        raise typer.Exit(code=1)

    # Gather Context
    system_context = {
        "os": sys.platform,
        "is_admin": is_admin(),
        "active_ports": EnvironmentInspector.get_listening_ports(),
    }
    
    if port:
        system_context["targeted_port_context"] = [
            p for p in system_context["active_ports"] if p["port"] == port
        ]

    prompt = f"""
    You are Sentinel, an expert system administrator and developer CLI tool.
    Analyze the following developer error log alongside the current system context.

    === ERROR LOG / ISSUE ===
    {log_text}

    === LOCAL SYSTEM TELEMETRY ===
    {json.dumps(system_context, indent=2)}

    Provide a concise, direct analysis in clear Markdown with:
    1. **Root Cause Analysis** (1-2 clear sentences)
    2. **Remediation Steps**
    3. **Executable Terminal Command(s)** to resolve the issue directly.
    """

    # Candidate models in order of priority
    candidate_models = [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "openai/gpt-oss-20b"
    ]

    client = Groq(api_key=api_key)
    response_text = None

    for model_id in candidate_models:
        console.print(f"[dim]Attempting telemetry analysis with model: {model_id}...[/dim]")
        try:
            chat_completion = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are Sentinel, a high-precision CLI diagnostic assistant."},
                    {"role": "user", "content": prompt}
                ],
                model=model_id,
            )
            response_text = chat_completion.choices[0].message.content
            break  # Exit loop as soon as a model successfully responds
        except Exception as e:
            if "model_not_found" in str(e) or "404" in str(e):
                console.print(f"[yellow]Model '{model_id}' unavailable, trying fallback...[/yellow]")
                continue
            else:
                console.print(f"[bold red]Groq Diagnostic Error ({model_id}):[/bold red] {e}")
                raise typer.Exit(code=1)

    if response_text:
        console.print(Panel(response_text, title="[bold green]Diagnostic & Resolution[/bold green]", border_style="green"))
    else:
        console.print("[bold red]All candidate Groq models failed. Check your API key or network connection.[/bold red]")


if __name__ == "__main__":
    app()