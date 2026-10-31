import os
import sys
import json
import threading
import flet as ft
import psutil
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# --- Core Logic Helpers ---
def get_listening_ports():
    ports = []
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as e:
        print(f"Error fetching network connections: {e}")
        return []

    for conn in connections:
        try:
            if conn.status == psutil.CONN_LISTEN:
                pid = conn.pid
                proc_name = "Unknown"
                if pid:
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                        proc_name = "[Restricted]"
                ports.append({
                    "port": str(conn.laddr.port),
                    "proto": "TCP" if conn.type == 1 else "UDP",
                    "pid": str(pid or "N/A"),
                    "process": proc_name
                })
        except Exception:
            continue
            
    return sorted(ports, key=lambda x: int(x["port"]))

def query_groq_ai(log_text: str, port_context: str = ""):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "Error: GROQ_API_KEY missing in .env file."
    
    system_context = {
        "os": sys.platform,
        "active_ports": get_listening_ports()[:10],
    }
    if port_context:
        system_context["target_port"] = port_context

    prompt = f"""
    You are Sentinel, an expert system administrator and developer CLI tool.
    Analyze the following developer error log alongside the system context.

    === ERROR LOG ===
    {log_text}

    === SYSTEM TELEMETRY ===
    {json.dumps(system_context, indent=2)}

    Provide a concise analysis with:
    1. **Root Cause**
    2. **Remediation Steps**
    3. **Command to fix**
    """

    candidate_models = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "openai/gpt-oss-20b"]
    client = Groq(api_key=api_key)

    for model in candidate_models:
        try:
            completion = client.chat.completions.create(
                messages=[{"role": "system", "content": "You are Sentinel, a high-precision CLI diagnostic assistant."},
                          {"role": "user", "content": prompt}],
                model=model,
            )
            return completion.choices[0].message.content
        except Exception:
            continue
    return "Error: All candidate Groq models failed to respond."

# --- Flet UI Main Application ---
def main(page: ft.Page):
    page.title = "Sentinel // Command Center"
    page.vertical_alignment = ft.MainAxisAlignment.START
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0b0f19"
    page.padding = 20
    page.window_width = 1100
    page.window_height = 750
    page.window_resizable = True

    # --- Header Component ---
    header = ft.Container(
        content=ft.Row(
            [
                ft.Row([
                    ft.Icon(ft.Icons.TERMINAL, color="#00ffcc", size=24),
                    ft.Text("SENTINEL // COMMAND CENTER", size=18, weight=ft.FontWeight.BOLD, color="#00ffcc"),
                ], spacing=10),
                ft.Container(
                    content=ft.Text("ONLINE & SECURE", size=11, weight=ft.FontWeight.BOLD, color="#0b0f19"),
                    bgcolor="#00ffcc",
                    padding=ft.Padding.symmetric(horizontal=8, vertical=4),
                    border_radius=4
                )
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN
        ),
        bgcolor="#111827",
        padding=15,
        border_radius=8,
        border=ft.Border.all(width=1, color="#1f2937")
    )

    # --- Left Pane: Port Table ---
    ports_data_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("PORT", color="#00ffcc", weight=ft.FontWeight.BOLD)),
            ft.DataColumn(ft.Text("PROTO", color="#94a3b8")),
            ft.DataColumn(ft.Text("PID", color="#94a3b8")),
            ft.DataColumn(ft.Text("PROCESS", color="#94a3b8")),
        ],
        rows=[],
        heading_row_color="#0f172a",
        data_row_color={"hover": "#1e293b"},
        border=ft.Border.all(width=1, color="#1f2937"),
        vertical_lines=ft.BorderSide(width=1, color="#1f2937"),
    )

    def update_port_table():
        ports_data_table.rows.clear()
        for p in get_listening_ports():
            ports_data_table.rows.append(
                ft.DataRow(
                    cells=[
                        ft.DataCell(ft.Text(p["port"], color="#e2e8f0", weight=ft.FontWeight.BOLD)),
                        ft.DataCell(ft.Text(p["proto"], color="#94a3b8")),
                        ft.DataCell(ft.Text(p["pid"], color="#94a3b8")),
                        ft.DataCell(ft.Text(p["process"], color="#cbd5e1")),
                    ]
                )
            )
        page.update()

    def handle_scan_click(e):
        update_port_table()
        page.snack_bar = ft.SnackBar(ft.Text("Network telemetry synchronized successfully!"), bgcolor="#111827")
        page.snack_bar.open = True
        page.update()

    scan_button = ft.Button(
        content="SCAN PORTS",
        icon=ft.Icons.REFRESH,
        color="#00ffcc",
        bgcolor="#1f2937",
        on_click=handle_scan_click,
        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=6))
    )

    port_section = ft.Container(
        content=ft.Column(
            [
                ft.Text("LOCAL NETWORK TELEMETRY", size=12, weight=ft.FontWeight.BOLD, color="#94a3b8"),
                ft.Column([ports_data_table], scroll=ft.ScrollMode.AUTO, height=420),
                scan_button
            ],
            spacing=12
        ),
        bgcolor="#111827",
        padding=15,
        border_radius=8,
        border=ft.Border.all(width=1, color="#1f2937"),
        expand=1
    )

    # --- Right Pane: AI Diagnostic Hub ---
    log_input = ft.TextField(
        label="Paste Error Log or Issue Description",
        multiline=True,
        min_lines=3,
        max_lines=5,
        border_color="#1f2937",
        focused_border_color="#00ffcc",
        label_style=ft.TextStyle(color="#94a3b8"),
        text_style=ft.TextStyle(color="#e2e8f0", size=13),
        bgcolor="#0f172a"
    )

    port_input = ft.TextField(
        label="Target Port Context (Optional)",
        border_color="#1f2937",
        focused_border_color="#00ffcc",
        label_style=ft.TextStyle(color="#94a3b8"),
        text_style=ft.TextStyle(color="#e2e8f0", size=13),
        bgcolor="#0f172a",
        height=50
    )

    ai_output_view = ft.Markdown(
        value="Awaiting telemetry input...",
        selectable=True,
        extension_set=ft.MarkdownExtensionSet.GITHUB_WEB,
    )

    ai_output_container = ft.Container(
        content=ai_output_view,
        bgcolor="#0f172a",
        padding=12,
        border_radius=6,
        border=ft.Border.all(width=1, color="#1f2937"),
        expand=True
    )

    def handle_analyze_click(e):
        if not log_input.value:
            page.snack_bar = ft.SnackBar(ft.Text("Please provide an error log."), bgcolor="red")
            page.snack_bar.open = True
            page.update()
            return

        ai_output_view.value = "_Consulting Groq models across nodes..._"
        page.update()

        def background_query():
            result = query_groq_ai(log_input.value, port_input.value)
            ai_output_view.value = result
            page.update()

        threading.Thread(target=background_query, daemon=True).start()

    analyze_button = ft.Button(
        content="ANALYZE ERROR",
        icon=ft.Icons.AUTO_AWESOME,
        color="#0b0f19",
        bgcolor="#00ffcc",
        on_click=handle_analyze_click,
        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=6))
    )

    ai_section = ft.Container(
        content=ft.Column(
            [
                ft.Text("GROQ AI DIAGNOSTIC ENGINE", size=12, weight=ft.FontWeight.BOLD, color="#94a3b8"),
                log_input,
                port_input,
                ai_output_container,
                analyze_button
            ],
            spacing=12,
            expand=True
        ),
        bgcolor="#111827",
        padding=15,
        border_radius=8,
        border=ft.Border.all(width=1, color="#1f2937"),
        expand=1
    )

    # --- Main Layout Assembly ---
    body_row = ft.Row([port_section, ai_section], spacing=15, expand=True)
    
    page.add(
        ft.Column([
            header,
            body_row
        ], spacing=15, expand=True)
    )

    update_port_table()

ft.run(main=main)