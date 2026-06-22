import tkinter as tk
from tkinter import ttk, messagebox
import nmap
import threading
import datetime
import os

# ─── Color Palette ───────────────────────────────────────────────────────────
BG_DARK      = "#0a0e1a"
BG_PANEL     = "#0f1526"
BG_CARD      = "#141b2d"
ACCENT_BLUE  = "#00aaff"
ACCENT_CYAN  = "#00e5ff"
ACCENT_GREEN = "#00ff88"
ACCENT_RED   = "#ff4455"
ACCENT_AMBER = "#ffb300"
TEXT_PRIMARY = "#e8eaf6"
TEXT_MUTED   = "#5a6a8a"
BORDER       = "#1e2d4a"

# ─── Main Application ─────────────────────────────────────────────────────────
class SecurityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("RUKAMCO — Network Vulnerability Scanner")
        self.root.geometry("900x680")
        self.root.configure(bg=BG_DARK)
        self.root.resizable(True, True)
        self.root.minsize(800, 600)

        self.scanning = False
        self._build_ui()

    # ── Build UI ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ──
        header = tk.Frame(self.root, bg=BG_DARK, pady=0)
        header.pack(fill="x", padx=0, pady=0)

        header_inner = tk.Frame(header, bg=BG_PANEL, pady=14)
        header_inner.pack(fill="x")

        # Glowing title line
        accent_line = tk.Frame(header_inner, bg=ACCENT_BLUE, height=2)
        accent_line.pack(fill="x")

        title_row = tk.Frame(header_inner, bg=BG_PANEL)
        title_row.pack(fill="x", padx=24, pady=(10, 6))

        tk.Label(
            title_row, text="⬡  RUKAMCO", font=("Courier New", 11, "bold"),
            fg=ACCENT_CYAN, bg=BG_PANEL
        ).pack(side="left")

        tk.Label(
            title_row, text="NETWORK VULNERABILITY SCANNER",
            font=("Courier New", 11, "bold"), fg=TEXT_PRIMARY, bg=BG_PANEL
        ).pack(side="left", padx=(8, 0))

        tk.Label(
            title_row, text="v1.0", font=("Courier New", 9),
            fg=TEXT_MUTED, bg=BG_PANEL
        ).pack(side="left", padx=(8, 0))

        self.status_dot = tk.Label(
            title_row, text="●  READY", font=("Courier New", 9, "bold"),
            fg=ACCENT_GREEN, bg=BG_PANEL
        )
        self.status_dot.pack(side="right")

        bottom_accent = tk.Frame(header_inner, bg=BORDER, height=1)
        bottom_accent.pack(fill="x")

        # ── Main Content ──
        content = tk.Frame(self.root, bg=BG_DARK)
        content.pack(fill="both", expand=True, padx=18, pady=(14, 10))

        # Left column: controls
        left = tk.Frame(content, bg=BG_DARK, width=280)
        left.pack(side="left", fill="y", padx=(0, 12))
        left.pack_propagate(False)

        self._build_controls(left)

        # Right column: output
        right = tk.Frame(content, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True)

        self._build_output(right)

        # ── Status Bar ──
        self._build_statusbar()

    def _build_controls(self, parent):
        # Target section
        self._section_label(parent, "TARGET")

        target_card = tk.Frame(parent, bg=BG_CARD, padx=14, pady=14,
                                highlightthickness=1, highlightbackground=BORDER)
        target_card.pack(fill="x", pady=(4, 0))

        tk.Label(target_card, text="IP Address / Hostname",
                 font=("Courier New", 8), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")

        self.entry = tk.Entry(
            target_card, font=("Courier New", 12, "bold"),
            bg="#0d1422", fg=ACCENT_CYAN, insertbackground=ACCENT_CYAN,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=ACCENT_BLUE, highlightcolor=ACCENT_CYAN
        )
        self.entry.pack(fill="x", pady=(6, 0), ipady=7)
        self.entry.insert(0, "192.168.1.1")
        self.entry.bind("<Return>", lambda e: self._start_scan_thread())

        # Scan type
        self._section_label(parent, "SCAN TYPE")

        scan_card = tk.Frame(parent, bg=BG_CARD, padx=14, pady=12,
                              highlightthickness=1, highlightbackground=BORDER)
        scan_card.pack(fill="x", pady=(4, 0))

        self.scan_var = tk.StringVar(value="quick")
        scans = [
            ("Quick Scan  (ports 1–1024)", "quick"),
            ("Full Scan   (ports 1–65535)", "full"),
            ("Ping Sweep  (host discovery)", "ping"),
        ]
        for label, val in scans:
            rb = tk.Radiobutton(
                scan_card, text=label, variable=self.scan_var, value=val,
                font=("Courier New", 9), fg=TEXT_PRIMARY, bg=BG_CARD,
                selectcolor=BG_DARK, activebackground=BG_CARD,
                activeforeground=ACCENT_CYAN, cursor="hand2"
            )
            rb.pack(anchor="w", pady=2)

        # Port range override
        self._section_label(parent, "PORT RANGE  (optional override)")

        port_card = tk.Frame(parent, bg=BG_CARD, padx=14, pady=12,
                              highlightthickness=1, highlightbackground=BORDER)
        port_card.pack(fill="x", pady=(4, 0))

        port_row = tk.Frame(port_card, bg=BG_CARD)
        port_row.pack(fill="x")

        tk.Label(port_row, text="From", font=("Courier New", 8),
                 fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
        self.port_from = tk.Entry(port_row, width=6, font=("Courier New", 10),
                                   bg="#0d1422", fg=ACCENT_CYAN, insertbackground=ACCENT_CYAN,
                                   relief="flat", highlightthickness=1,
                                   highlightbackground=BORDER)
        self.port_from.pack(side="left", padx=(6, 0), ipady=4)
        self.port_from.insert(0, "1")

        tk.Label(port_row, text="  To", font=("Courier New", 8),
                 fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
        self.port_to = tk.Entry(port_row, width=6, font=("Courier New", 10),
                                 bg="#0d1422", fg=ACCENT_CYAN, insertbackground=ACCENT_CYAN,
                                 relief="flat", highlightthickness=1,
                                 highlightbackground=BORDER)
        self.port_to.pack(side="left", padx=(6, 0), ipady=4)
        self.port_to.insert(0, "1024")

        # Buttons
        self._section_label(parent, "ACTIONS")

        btn_frame = tk.Frame(parent, bg=BG_DARK)
        btn_frame.pack(fill="x", pady=(6, 0))

        self.scan_btn = tk.Button(
            btn_frame, text="▶  START SCAN",
            font=("Courier New", 10, "bold"), fg=BG_DARK,
            bg=ACCENT_CYAN, activebackground=ACCENT_BLUE,
            activeforeground=BG_DARK, relief="flat", cursor="hand2",
            command=self._start_scan_thread, pady=10
        )
        self.scan_btn.pack(fill="x", pady=(0, 6))

        self.clear_btn = tk.Button(
            btn_frame, text="⊘  CLEAR OUTPUT",
            font=("Courier New", 9), fg=TEXT_MUTED,
            bg=BG_CARD, activebackground=BORDER,
            activeforeground=TEXT_PRIMARY, relief="flat", cursor="hand2",
            command=self._clear_output, pady=8,
            highlightthickness=1, highlightbackground=BORDER
        )
        self.clear_btn.pack(fill="x", pady=(0, 6))

        self.save_btn = tk.Button(
            btn_frame, text="⬇  SAVE REPORT",
            font=("Courier New", 9), fg=TEXT_MUTED,
            bg=BG_CARD, activebackground=BORDER,
            activeforeground=TEXT_PRIMARY, relief="flat", cursor="hand2",
            command=self._manual_save, pady=8,
            highlightthickness=1, highlightbackground=BORDER
        )
        self.save_btn.pack(fill="x")

        # Stats
        self._section_label(parent, "LAST SCAN STATS")

        stats_card = tk.Frame(parent, bg=BG_CARD, padx=14, pady=12,
                               highlightthickness=1, highlightbackground=BORDER)
        stats_card.pack(fill="x", pady=(4, 0))

        self.stat_hosts   = self._stat_row(stats_card, "Hosts Found",  "—")
        self.stat_open    = self._stat_row(stats_card, "Open Ports",   "—")
        self.stat_elapsed = self._stat_row(stats_card, "Elapsed",      "—")

    def _build_output(self, parent):
        self._section_label(parent, "SCAN OUTPUT")

        out_frame = tk.Frame(parent, bg=BG_CARD,
                              highlightthickness=1, highlightbackground=BORDER)
        out_frame.pack(fill="both", expand=True, pady=(4, 0))

        # Inner top bar
        top_bar = tk.Frame(out_frame, bg="#0b1020", pady=6, padx=10)
        top_bar.pack(fill="x")

        tk.Label(top_bar, text="terminal@rukamco-scanner",
                 font=("Courier New", 8), fg=TEXT_MUTED, bg="#0b1020").pack(side="left")

        self.progress = tk.Label(top_bar, text="",
                                  font=("Courier New", 8, "bold"),
                                  fg=ACCENT_AMBER, bg="#0b1020")
        self.progress.pack(side="right")

        # Text output
        text_frame = tk.Frame(out_frame, bg=BG_CARD)
        text_frame.pack(fill="both", expand=True, padx=2, pady=2)

        self.result = tk.Text(
            text_frame,
            font=("Courier New", 10),
            bg="#060c18", fg=TEXT_PRIMARY,
            insertbackground=ACCENT_CYAN,
            relief="flat", bd=0,
            wrap="word",
            padx=14, pady=12,
            spacing1=2, spacing3=2
        )
        self.result.pack(side="left", fill="both", expand=True)

        scrollbar = tk.Scrollbar(text_frame, command=self.result.yview,
                                  bg=BG_DARK, troughcolor=BG_PANEL,
                                  activebackground=ACCENT_BLUE, relief="flat")
        scrollbar.pack(side="right", fill="y")
        self.result.configure(yscrollcommand=scrollbar.set)

        # Tag colors
        self.result.tag_config("header",  foreground=ACCENT_CYAN,  font=("Courier New", 11, "bold"))
        self.result.tag_config("host",    foreground=ACCENT_BLUE,  font=("Courier New", 10, "bold"))
        self.result.tag_config("open",    foreground=ACCENT_GREEN, font=("Courier New", 10))
        self.result.tag_config("closed",  foreground=TEXT_MUTED,   font=("Courier New", 10))
        self.result.tag_config("proto",   foreground=ACCENT_AMBER, font=("Courier New", 10, "bold"))
        self.result.tag_config("error",   foreground=ACCENT_RED,   font=("Courier New", 10, "bold"))
        self.result.tag_config("muted",   foreground=TEXT_MUTED,   font=("Courier New", 9))
        self.result.tag_config("state_up",   foreground=ACCENT_GREEN)
        self.result.tag_config("state_down", foreground=ACCENT_RED)

        self._print_banner()

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=BG_PANEL, pady=5,
                        highlightthickness=1, highlightbackground=BORDER)
        bar.pack(fill="x", side="bottom")

        self.statusbar = tk.Label(
            bar, text="Ready — enter a target IP and press Start Scan",
            font=("Courier New", 8), fg=TEXT_MUTED, bg=BG_PANEL, anchor="w"
        )
        self.statusbar.pack(side="left", padx=14)

        tk.Label(bar, text="Rukamco LLC — Network Security Project  2025",
                 font=("Courier New", 8), fg=TEXT_MUTED, bg=BG_PANEL).pack(side="right", padx=14)

    # ── Helper Widgets ────────────────────────────────────────────────────────
    def _section_label(self, parent, text):
        row = tk.Frame(parent, bg=BG_DARK)
        row.pack(fill="x", pady=(14, 0))
        tk.Label(row, text=text, font=("Courier New", 7, "bold"),
                 fg=TEXT_MUTED, bg=BG_DARK).pack(side="left")
        tk.Frame(row, bg=BORDER, height=1).pack(side="left", fill="x", expand=True, padx=(8, 0))

    def _stat_row(self, parent, label, value):
        row = tk.Frame(parent, bg=BG_CARD)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=label, font=("Courier New", 8),
                 fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
        lbl = tk.Label(row, text=value, font=("Courier New", 9, "bold"),
                        fg=ACCENT_CYAN, bg=BG_CARD)
        lbl.pack(side="right")
        return lbl

    # ── Banner ────────────────────────────────────────────────────────────────
    def _print_banner(self):
        self.result.config(state="normal")
        banner = (
            "┌─────────────────────────────────────────────────────┐\n"
            "│      RUKAMCO LLC — NETWORK VULNERABILITY SCANNER    │\n"
            "│      Cybersecurity Project  ·  MEC 2025             │\n"
            "└─────────────────────────────────────────────────────┘\n\n"
            "  Enter a target IP address in the panel on the left,\n"
            "  select a scan type, then press  ▶ START SCAN.\n\n"
            "  Reports are saved automatically to scan_report.txt\n"
        )
        self.result.insert("end", banner, "muted")
        self.result.config(state="disabled")

    # ── Scan Logic ────────────────────────────────────────────────────────────
    def _start_scan_thread(self):
        if self.scanning:
            return
        self.scanning = True
        t = threading.Thread(target=self._run_scan, daemon=True)
        t.start()

    def _run_scan(self):
        target = self.entry.get().strip()
        if not target:
            self._append("  ⚠ No target specified.\n", "error")
            self.scanning = False
            return

        scan_type = self.scan_var.get()
        port_range = f"{self.port_from.get()}-{self.port_to.get()}"

        if scan_type == "quick":
            port_range = "1-1024"
        elif scan_type == "full":
            port_range = "1-65535"

        self._set_status("SCANNING", ACCENT_AMBER)
        self._update_statusbar(f"Scanning {target} …")
        self._update_progress("● scanning…")
        self.scan_btn.config(state="disabled", bg=TEXT_MUTED)

        self.result.config(state="normal")
        self.result.delete("1.0", "end")
        self.result.config(state="disabled")

        ts = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self._append(f"\n  ═══ SCAN STARTED  {ts} ═══\n", "header")
        self._append(f"  Target     :  {target}\n", "muted")
        self._append(f"  Port Range :  {port_range}\n", "muted")
        self._append(f"  Scan Type  :  {scan_type.upper()}\n\n", "muted")

        start = datetime.datetime.now()
        open_count = 0
        host_count = 0

        try:
            scanner = nmap.PortScanner()

            if scan_type == "ping":
                scanner.scan(hosts=target, arguments="-sn")
            else:
                scanner.scan(target, port_range)

            hosts = scanner.all_hosts()
            host_count = len(hosts)

            if not hosts:
                self._append("  ⚠ No hosts found. Check the target or your network.\n", "error")
            else:
                for host in hosts:
                    self._append(f"\n  ┌─ HOST: {host} ", "host")
                    state = scanner[host].state()
                    tag = "state_up" if state == "up" else "state_down"
                    self._append(f"[{state.upper()}]\n", tag)

                    # Hostname
                    hostnames = scanner[host].hostnames()
                    if hostnames:
                        self._append(f"  │  Hostname  : {hostnames[0].get('name', '—')}\n", "muted")

                    if scan_type != "ping":
                        for proto in scanner[host].all_protocols():
                            self._append(f"  │  Protocol  : {proto.upper()}\n", "proto")
                            ports = sorted(scanner[host][proto].keys())
                            for port in ports:
                                port_state = scanner[host][proto][port]["state"]
                                service    = scanner[host][proto][port].get("name", "")
                                if port_state == "open":
                                    open_count += 1
                                    self._append(
                                        f"  │  ✓  {str(port).ljust(6)} OPEN    {service}\n", "open"
                                    )
                                else:
                                    self._append(
                                        f"  │     {str(port).ljust(6)} {port_state}\n", "closed"
                                    )

                    self._append("  └" + "─" * 40 + "\n", "muted")

            elapsed = (datetime.datetime.now() - start).seconds
            self._append(f"\n  ═══ SCAN COMPLETE  —  {elapsed}s elapsed ═══\n\n", "header")

            # Update stats
            self.stat_hosts.config(text=str(host_count))
            self.stat_open.config(text=str(open_count))
            self.stat_elapsed.config(text=f"{elapsed}s")

            self._save_report(target, scanner, ts, port_range, open_count)
            self._update_statusbar(f"Scan complete — {host_count} host(s), {open_count} open port(s)")
            self._set_status("READY", ACCENT_GREEN)

        except Exception as e:
            self._append(f"\n  ✗ ERROR: {str(e)}\n", "error")
            self._append("  Make sure Nmap is installed and you have permission to scan.\n", "muted")
            self._set_status("ERROR", ACCENT_RED)
            self._update_statusbar("Scan failed — check Nmap installation")

        self._update_progress("")
        self.scan_btn.config(state="normal", bg=ACCENT_CYAN)
        self.scanning = False

    # ── Output Helpers ────────────────────────────────────────────────────────
    def _append(self, text, tag=""):
        self.result.config(state="normal")
        if tag:
            self.result.insert("end", text, tag)
        else:
            self.result.insert("end", text)
        self.result.see("end")
        self.result.config(state="disabled")
        self.root.update_idletasks()

    def _clear_output(self):
        self.result.config(state="normal")
        self.result.delete("1.0", "end")
        self.result.config(state="disabled")
        self._print_banner()
        self.stat_hosts.config(text="—")
        self.stat_open.config(text="—")
        self.stat_elapsed.config(text="—")
        self._update_statusbar("Output cleared")

    def _set_status(self, text, color):
        self.status_dot.config(text=f"●  {text}", fg=color)

    def _update_statusbar(self, text):
        self.statusbar.config(text=f"  {text}")

    def _update_progress(self, text):
        self.progress.config(text=text)

    # ── Report ────────────────────────────────────────────────────────────────
    def _save_report(self, target, scanner, ts, port_range, open_count):
        try:
            with open("scan_report.txt", "w") as f:
                f.write("=" * 60 + "\n")
                f.write("  RUKAMCO LLC — NETWORK VULNERABILITY SCAN REPORT\n")
                f.write("  Cybersecurity Project · MEC 2025\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Scan Date  : {ts}\n")
                f.write(f"Target     : {target}\n")
                f.write(f"Port Range : {port_range}\n")
                f.write(f"Open Ports : {open_count}\n\n")

                for host in scanner.all_hosts():
                    f.write(f"HOST: {host}  [{scanner[host].state().upper()}]\n")
                    for proto in scanner[host].all_protocols():
                        f.write(f"  Protocol: {proto.upper()}\n")
                        for port in sorted(scanner[host][proto].keys()):
                            state   = scanner[host][proto][port]["state"]
                            service = scanner[host][proto][port].get("name", "")
                            f.write(f"    Port {port:6d}: {state:10s}  {service}\n")
                    f.write("\n")

                f.write("=" * 60 + "\n")
                f.write("Report generated automatically by RUKAMCO Scanner\n")

            self._append("  ✓ Report saved → scan_report.txt\n", "open")
        except Exception as e:
            self._append(f"  ⚠ Could not save report: {e}\n", "error")

    def _manual_save(self):
        messagebox.showinfo(
            "Save Report",
            "Reports are saved automatically as scan_report.txt\nafter every scan completes."
        )


# ─── Entry Point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityScanner(root)
    root.mainloop()
