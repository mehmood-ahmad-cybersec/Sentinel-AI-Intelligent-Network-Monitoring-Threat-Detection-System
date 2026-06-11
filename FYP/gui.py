import customtkinter as ctk
from tkinter import ttk, messagebox
import threading
import time
import psutil
import sqlite3
import csv
import math
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from scanner import scan_network
from database import create_db, save_devices
from port_scanner import scan_ports, check_danger_ports
import ai_anomaly

ctk.set_appearance_mode("dark")

# ===== COLOR PALETTE =====
BG          = "#0b0f2a"
SIDEBAR     = "#0d1117"
CARD1       = "#7c3aed"
CARD2       = "#06b6d4"
CARD3       = "#ec4899"
CARD4       = "#f59e0b"
BLUE        = "#6366f1"
GREEN       = "#10b981"
RED         = "#ef4444"
YELLOW      = "#f59e0b"
TEXT        = "#e5e7eb"
SUBTEXT     = "#9ca3af"
TABLE_BG    = "#0f172a"
TABLE_HEAD  = "#1e1b4b"
CARD_BG     = "#111827"


class NetworkGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SENTINEL AI — Network Security Dashboard")
        self.geometry("1400x900")
        self.minsize(1200, 750)

        self.ai_running      = False
        self.last_alert_time = 0
        self.device_count    = 0
        self.threat_count    = 0
        self.alert_count     = 0

        self._radar_angle  = 0
        self._radar_job    = None
        self._shield_job   = None
        self._shield_phase = 0
        self._splash_job   = None
        self._splash_angle = 0
        self._splash_pulse = 0

        # Email settings
        self._alert_email    = ""
        self._alert_password = ""
        self._email_enabled  = False

        create_db()
        self._show_landing()

    # =========================================================
    #  EMAIL ALERT
    # =========================================================
    def _send_email_alert(self, subject, body):
        """Send email alert in background thread — never blocks UI."""
        if not self._email_enabled or not self._alert_email or not self._alert_password:
            return

        def _send():
            try:
                msg = MIMEMultipart()
                msg["From"]    = self._alert_email
                msg["To"]      = self._alert_email
                msg["Subject"] = subject
                msg.attach(MIMEText(body, "plain"))

                with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
                    server.login(self._alert_email, self._alert_password)
                    server.sendmail(self._alert_email, self._alert_email, msg.as_string())
            except Exception as e:
                print(f"[Email Error] {e}")

        threading.Thread(target=_send, daemon=True).start()

    # =========================================================
    #  LANDING SCREEN
    # =========================================================
    def _show_landing(self):
        self.configure(fg_color=BG)
        for w in self.winfo_children():
            w.destroy()

        self.splash_canvas = ctk.CTkCanvas(self, bg=BG, highlightthickness=0)
        self.splash_canvas.pack(fill="both", expand=True)

        self._splash_angle = 0
        self._splash_pulse = 0
        self._animate_splash()

        content = ctk.CTkFrame(self.splash_canvas, fg_color="transparent")
        content.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(content, text="⚡", font=("Segoe UI", 72)).pack(pady=(0, 4))
        ctk.CTkLabel(content, text="SENTINEL AI",
                     font=("Segoe UI", 54, "bold"), text_color=TEXT).pack()
        ctk.CTkLabel(content,
                     text="Real-time Network Security & Threat Intelligence System",
                     font=("Segoe UI", 15), text_color=SUBTEXT).pack(pady=(6, 40))

        pills = ctk.CTkFrame(content, fg_color="transparent")
        pills.pack(pady=(0, 40))
        for icon, label, color in [
            ("🌐", "Network Scan",     CARD1),
            ("🤖", "AI Monitoring",    CARD2),
            ("🛡️", "Threat Detection", CARD3),
            ("📂", "Device Logging",   CARD4),
        ]:
            pill = ctk.CTkFrame(pills, fg_color=color, corner_radius=20)
            pill.pack(side="left", padx=8)
            ctk.CTkLabel(pill, text=f"  {icon} {label}  ",
                         font=("Segoe UI", 12, "bold"), text_color="white").pack(pady=8, padx=4)

        ctk.CTkButton(content, text="  ▶   ENTER DASHBOARD  ",
                      command=self._launch_main,
                      fg_color=BLUE, hover_color="#4338ca",
                      font=("Segoe UI", 16, "bold"),
                      height=54, corner_radius=14, width=280).pack(pady=8)

        ctk.CTkLabel(content,
                     text="MEHMOOD AHMAD  |  BSIT Final Year Project",
                     font=("Segoe UI", 11), text_color="#374151").pack(pady=(28, 0))

    def _animate_splash(self):
        if not hasattr(self, 'splash_canvas'):
            return
        c = self.splash_canvas
        c.delete("all")
        try:
            W = self.winfo_width()  or 1400
            H = self.winfo_height() or 900
        except Exception:
            return
        cx, cy = W // 2, H // 2
        self._splash_angle = (self._splash_angle + 0.4) % 360
        self._splash_pulse  = (self._splash_pulse + 1) % 100

        for r in range(60, max(W, H), 80):
            shade = max(0, 20 - r // 80)
            col   = f"#{shade:02x}{shade + 3:02x}{min(shade + 15, 42):02x}"
            c.create_oval(cx - r, cy - r, cx + r, cy + r, outline=col, width=1)

        for i in range(12):
            angle = math.radians(self._splash_angle + i * 30)
            xe = cx + max(W, H) * math.cos(angle)
            ye = cy + max(W, H) * math.sin(angle)
            c.create_line(cx, cy, xe, ye, fill="#0e1434", width=1)

        pulse_r = 100 + self._splash_pulse * 2.5
        c.create_oval(cx - pulse_r, cy - pulse_r, cx + pulse_r, cy + pulse_r,
                      outline="#1a1e3a", width=40)

        self._splash_job = self.after(30, self._animate_splash)

    def _launch_main(self):
        if self._splash_job:
            self.after_cancel(self._splash_job)
            self._splash_job = None
        for w in self.winfo_children():
            w.destroy()
        self._build_layout()
        # All pages built once — switch with tkraise(), zero flicker
        self._build_all_pages()
        self.show_home()

    # =========================================================
    #  MAIN LAYOUT
    # =========================================================
    def _build_layout(self):
        # SIDEBAR
        self.sidebar = ctk.CTkFrame(self, width=240, fg_color=SIDEBAR, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        logo_f = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_f.pack(fill="x", pady=(28, 4), padx=20)
        ctk.CTkLabel(logo_f, text="⚡", font=("Segoe UI", 26)).pack(side="left")
        ctk.CTkLabel(logo_f, text=" SENTINEL AI",
                     font=("Segoe UI", 20, "bold"), text_color=TEXT).pack(side="left")
        ctk.CTkLabel(self.sidebar, text="Network Security Suite",
                     font=("Segoe UI", 11), text_color=SUBTEXT).pack(pady=(0, 20))

        ctk.CTkFrame(self.sidebar, height=1, fg_color="#1f2937").pack(fill="x", padx=20, pady=(0, 15))

        ctk.CTkLabel(self.sidebar, text="MENU",
                     font=("Segoe UI", 10, "bold"), text_color="#4b5563").pack(anchor="w", padx=25, pady=(0, 6))

        self._nav_buttons = {}
        for icon, label, cmd in [
            ("🏠", "Dashboard",    self.show_home),
            ("🌐", "Network Scan", self.show_scan),
            ("🤖", "AI Monitor",   self.show_ai),
            ("📂", "DB Logs",      self.show_logs),
            ("📧", "Email Alerts", self.show_email),
        ]:
            self._nav_buttons[label] = self._nav_btn(icon, label, cmd)

        ctk.CTkFrame(self.sidebar, height=1, fg_color="#1f2937").pack(fill="x", padx=20, pady=15)

        self.status_lbl = ctk.CTkLabel(self.sidebar, text="● SYSTEM READY",
                                       font=("Segoe UI", 12, "bold"), text_color=SUBTEXT)
        self.status_lbl.pack(pady=6)
        self.live_traffic = ctk.CTkLabel(self.sidebar, text="Traffic: 0 KB/s",
                                         font=("Segoe UI", 12), text_color=SUBTEXT)
        self.live_traffic.pack(pady=2)

        # Email status indicator in sidebar
        self.email_status_lbl = ctk.CTkLabel(self.sidebar, text="📧 Email: OFF",
                                             font=("Segoe UI", 11), text_color=SUBTEXT)
        self.email_status_lbl.pack(pady=2)

        ctk.CTkButton(self.sidebar, text="📥  Export CSV Report",
                      command=self.export_to_file,
                      fg_color="transparent", border_width=2, border_color=BLUE,
                      hover_color="#1e1b4b", font=("Segoe UI", 12, "bold"),
                      height=40, corner_radius=10).pack(pady=18, padx=18, fill="x")

        ctk.CTkLabel(self.sidebar,
                     text="MEHMOOD AHMAD | BSIT\nFinal Year Project",
                     font=("Segoe UI", 10), text_color="#374151").pack(side="bottom", pady=18)

        # RIGHT COLUMN
        right_col = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        right_col.pack(side="right", fill="both", expand=True)

        # TOP NAVBAR
        self.topbar = ctk.CTkFrame(right_col, height=58, fg_color=SIDEBAR, corner_radius=0)
        self.topbar.pack(fill="x")
        self.topbar.pack_propagate(False)

        search_frame = ctk.CTkFrame(self.topbar, fg_color="#1f2937", corner_radius=8)
        search_frame.pack(side="left", padx=24, pady=10)
        ctk.CTkLabel(search_frame, text="🔍", font=("Segoe UI", 14)).pack(side="left", padx=(10, 4))
        self._search_var = ctk.StringVar()
        self._search_var.trace_add("write", self._on_search)
        self._search_entry = ctk.CTkEntry(search_frame,
                     textvariable=self._search_var,
                     placeholder_text="Search devices, IPs, MACs...",
                     fg_color="transparent", border_width=0,
                     text_color=TEXT, font=("Segoe UI", 12),
                     width=220, height=30)
        self._search_entry.pack(side="left", padx=(0, 10))

        right_icons = ctk.CTkFrame(self.topbar, fg_color="transparent")
        right_icons.pack(side="right", padx=20, pady=8)

        ctk.CTkButton(right_icons, text="🔔",
                      fg_color="transparent", hover_color="#1f2937",
                      font=("Segoe UI", 18), width=40, height=40,
                      corner_radius=8).pack(side="left", padx=4)

        ctk.CTkLabel(right_icons, text="●",
                     font=("Segoe UI", 16), text_color=GREEN).pack(side="left", padx=(4, 2))
        ctk.CTkLabel(right_icons, text="Live",
                     font=("Segoe UI", 12), text_color=TEXT).pack(side="left", padx=(0, 12))

        profile = ctk.CTkFrame(right_icons, fg_color=CARD1, corner_radius=20, width=38, height=38)
        profile.pack(side="left", padx=4)
        profile.pack_propagate(False)
        ctk.CTkLabel(profile, text="MA", font=("Segoe UI", 12, "bold"),
                     text_color="white").place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(right_icons, text="Mehmood",
                     font=("Segoe UI", 13), text_color=TEXT).pack(side="left", padx=(6, 4))

        # PAGE CONTAINER — all pages stacked here, tkraise() switches them
        self._page_container = ctk.CTkFrame(right_col, fg_color=BG, corner_radius=0)
        self._page_container.pack(fill="both", expand=True)

    # =========================================================
    #  BUILD ALL PAGES ONCE (no destroy/rebuild = no flicker)
    # =========================================================
    def _build_all_pages(self):
        """Create all page frames once. Switch with tkraise()."""
        self._pages = {}

        for name in ["home", "scan", "ai", "logs", "email"]:
            f = ctk.CTkFrame(self._page_container, fg_color=BG, corner_radius=0)
            f.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._pages[name] = f

        self._build_home_page(self._pages["home"])
        self._build_scan_page(self._pages["scan"])
        self._build_ai_page(self._pages["ai"])
        self._build_logs_page(self._pages["logs"])
        self._build_email_page(self._pages["email"])

    def _switch_page(self, name):
        self._pages[name].tkraise()

    # =========================================================
    #  NAV / HELPERS
    # =========================================================
    def _nav_btn(self, icon, label, cmd):
        frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        frame.pack(fill="x", padx=10, pady=2)

        def on_click():
            self._stop_all_animations()
            self._set_active(label)
            cmd()

        btn = ctk.CTkButton(frame, text=f"  {icon}  {label}",
                            command=on_click,
                            fg_color="transparent", hover_color="#1f2937",
                            anchor="w", font=("Segoe UI", 13), height=40, corner_radius=10)
        btn.pack(fill="x")
        return btn

    def _set_active(self, active_label):
        for label, btn in self._nav_buttons.items():
            btn.configure(fg_color=BLUE if label == active_label else "transparent")

    def _stop_all_animations(self):
        for attr in ("_radar_job", "_shield_job", "_splash_job"):
            job = getattr(self, attr, None)
            if job:
                try:
                    self.after_cancel(job)
                except Exception:
                    pass
                setattr(self, attr, None)

    def _on_search(self, *args):
        if not hasattr(self, 'tree'):
            return
        query = self._search_var.get().strip().lower()
        if not hasattr(self, '_all_scan_rows'):
            return
        for i in self.tree.get_children():
            self.tree.delete(i)
        for row in self._all_scan_rows:
            if (query == "" or
                    query in str(row[1]).lower() or
                    query in str(row[2]).lower() or
                    query in str(row[3]).lower()):
                self.tree.insert("", "end",
                                 values=(row[0], row[1], row[2], row[3]),
                                 tags=(row[4],))
        self.tree.tag_configure("danger", foreground=RED)
        self.tree.tag_configure("safe",   foreground=GREEN)

    def _page_header(self, parent, title, subtitle=""):
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=30, pady=(22, 8))
        ctk.CTkLabel(hdr, text=title, font=("Segoe UI", 26, "bold"), text_color=TEXT).pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(hdr, text=subtitle, font=("Segoe UI", 12), text_color=SUBTEXT).pack(anchor="w")
        ctk.CTkFrame(parent, height=1, fg_color="#1f2937").pack(fill="x", padx=30, pady=(4, 0))

    # =========================================================
    #  SHOW METHODS (just raise the pre-built page)
    # =========================================================
    def show_home(self):
        self._set_active("Dashboard")
        # Refresh live stats on dashboard cards
        self._refresh_home_cards()
        self._switch_page("home")

    def show_scan(self):
        self._set_active("Network Scan")
        self._switch_page("scan")

    def show_ai(self):
        self._set_active("AI Monitor")
        self._switch_page("ai")
        # Restart idle shield if not running
        if not self.ai_running and not self._shield_job:
            self._shield_phase = 0
            self._draw_shield(active=False)

    def show_logs(self):
        self._set_active("DB Logs")
        self._switch_page("logs")
        self.load_logs()

    def show_email(self):
        self._set_active("Email Alerts")
        self._switch_page("email")

    # =========================================================
    #  DASHBOARD PAGE
    # =========================================================
    def _build_home_page(self, parent):
        self._page_header(parent, "Dashboard", "Real-time network security overview")

        self._home_cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._home_cards_frame.pack(fill="x", padx=30, pady=16)

        # Placeholder cards — refreshed on show_home()
        self._home_card_labels = {}
        cards_data = [
            ("🖥️", "Active Devices", "0",  "Scanned on LAN",       CARD1),
            ("⚠️",  "Threats Found",  "0",  "Dangerous open ports",  CARD2),
            ("🚨",  "AI Alerts",      "0",  "Traffic anomalies",     CARD3),
            ("🛡️",  "Security Score", "—",  "Based on scan results", CARD4),
        ]
        for col, (icon, title, value, sub, color) in enumerate(cards_data):
            val_lbl = self._stat_card(self._home_cards_frame, icon, title, value, sub, color, col)
            self._home_card_labels[title] = val_lbl
            self._home_cards_frame.grid_columnconfigure(col, weight=1)

        info = ctk.CTkFrame(parent, fg_color=CARD_BG, corner_radius=14)
        info.pack(fill="x", padx=30, pady=8)
        ctk.CTkLabel(info, text="📋  Quick Start Guide",
                     font=("Segoe UI", 15, "bold"), text_color=TEXT).pack(anchor="w", padx=22, pady=(16, 6))
        for num, txt in [
            ("1.", "Network Scan → START SCAN — discovers all LAN devices with IP, MAC & open ports"),
            ("2.", "AI Monitor → START AI MONITOR — trains baseline then detects traffic anomalies"),
            ("3.", "DB Logs → REFRESH — view all previously discovered devices from database"),
            ("4.", "Email Alerts → add Gmail to get instant email alerts on threats & anomalies"),
        ]:
            row = ctk.CTkFrame(info, fg_color="transparent")
            row.pack(fill="x", padx=22, pady=3)
            ctk.CTkLabel(row, text=num, font=("Segoe UI", 12, "bold"),
                         text_color=BLUE, width=26).pack(side="left")
            ctk.CTkLabel(row, text=txt, font=("Segoe UI", 12),
                         text_color=SUBTEXT, wraplength=800, justify="left").pack(side="left")
        ctk.CTkFrame(info, height=1, fg_color="#1f2937").pack(fill="x", padx=22, pady=10)
        ctk.CTkLabel(info, text="Mehmood Ahmad | BSIT Final Year Project",
                     font=("Segoe UI", 10), text_color="#374151").pack(anchor="w", padx=22, pady=(0, 12))

    def _refresh_home_cards(self):
        score_val, score_color = self._calc_score()
        updates = {
            "Active Devices": (str(self.device_count), CARD1),
            "Threats Found":  (str(self.threat_count), CARD2),
            "AI Alerts":      (str(self.alert_count),  CARD3),
            "Security Score": (score_val,               score_color),
        }
        for title, (val, _) in updates.items():
            if title in self._home_card_labels:
                self._home_card_labels[title].configure(text=val)

    def _calc_score(self):
        if self.device_count == 0:
            return "—", CARD4
        threat_ratio = self.threat_count / max(self.device_count, 1)
        score = max(0, int(100 - threat_ratio * 100))
        if score >= 80:
            return f"{score}%", GREEN
        elif score >= 50:
            return f"{score}%", YELLOW
        return f"{score}%", RED

    def _stat_card(self, parent, icon, title, value, sub, color, col):
        frame = ctk.CTkFrame(parent, fg_color=color, corner_radius=16, height=128)
        frame.grid(row=0, column=col, padx=7, sticky="nsew")
        frame.grid_propagate(False)
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 0))
        ctk.CTkLabel(top, text=icon, font=("Segoe UI", 20)).pack(side="left")
        val_lbl = ctk.CTkLabel(frame, text=value,
                               font=("Segoe UI", 34, "bold"), text_color="white")
        val_lbl.pack(anchor="w", padx=16)
        ctk.CTkLabel(frame, text=title,
                     font=("Segoe UI", 12, "bold"), text_color="white").pack(anchor="w", padx=16)
        ctk.CTkLabel(frame, text=sub,
                     font=("Segoe UI", 10), text_color="#d1d5db").pack(anchor="w", padx=16)
        return val_lbl  # return so we can update it

    # =========================================================
    #  NETWORK SCAN PAGE
    # =========================================================
    def _build_scan_page(self, parent):
        self._page_header(parent, "🌐 Network Scanner",
                          "Discover devices, open ports and security threats on your LAN")

        top = ctk.CTkFrame(parent, fg_color=CARD_BG, corner_radius=14)
        top.pack(fill="x", padx=30, pady=14)

        self.radar_canvas = ctk.CTkCanvas(top, bg=CARD_BG, width=320, height=240,
                                          highlightthickness=0)
        self.radar_canvas.pack(side="left", padx=18, pady=14)

        ctrl = ctk.CTkFrame(top, fg_color="transparent")
        ctrl.pack(side="left", fill="both", expand=True, padx=20, pady=20)

        self.scan_count_lbl = ctk.CTkLabel(ctrl, text="Active Devices: —",
                                           font=("Segoe UI", 22, "bold"), text_color=GREEN)
        self.scan_count_lbl.pack(anchor="w", pady=(8, 4))

        self.scan_status_lbl = ctk.CTkLabel(ctrl,
                                            text="Press START SCAN to begin network discovery",
                                            font=("Segoe UI", 12), text_color=SUBTEXT)
        self.scan_status_lbl.pack(anchor="w")

        stats_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        stats_row.pack(anchor="w", pady=10)
        self.scan_threat_lbl = ctk.CTkLabel(stats_row, text="Threats: —",
                                            font=("Segoe UI", 13, "bold"), text_color=RED)
        self.scan_threat_lbl.pack(side="left", padx=(0, 20))
        self.scan_secure_lbl = ctk.CTkLabel(stats_row, text="Secure: —",
                                            font=("Segoe UI", 13, "bold"), text_color=GREEN)
        self.scan_secure_lbl.pack(side="left")

        ctk.CTkButton(ctrl, text="▶  START SCAN", command=self.run_scan,
                      fg_color=BLUE, hover_color="#4338ca",
                      font=("Segoe UI", 14, "bold"), height=44,
                      corner_radius=10, width=170).pack(anchor="w", pady=10)

        self.table_outer = ctk.CTkFrame(parent, fg_color=TABLE_BG, corner_radius=14)
        self.table_outer.pack(fill="both", expand=True, padx=30, pady=(0, 22))

        tbl_hdr = ctk.CTkFrame(self.table_outer, fg_color="#0f1629", corner_radius=0, height=40)
        tbl_hdr.pack(fill="x")
        tbl_hdr.pack_propagate(False)
        ctk.CTkLabel(tbl_hdr, text="● ● ●  DEVICE SCAN RESULTS",
                     font=("Consolas", 11, "bold"), text_color=SUBTEXT).pack(side="left", padx=14, pady=10)

        self.empty_lbl = ctk.CTkLabel(self.table_outer,
                                      text="No scan data yet.\nClick  START SCAN  to discover devices.",
                                      font=("Segoe UI", 14), text_color=SUBTEXT)
        self.empty_lbl.pack(expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("S.Treeview",
                        background=TABLE_BG, foreground=TEXT, fieldbackground=TABLE_BG,
                        rowheight=40, font=("Segoe UI", 12), borderwidth=0)
        style.configure("S.Treeview.Heading",
                        background=TABLE_HEAD, foreground=TEXT,
                        font=("Segoe UI", 12, "bold"), relief="flat")
        style.map("S.Treeview", background=[("selected", "#1e1b4b")])

        self.tree = ttk.Treeview(self.table_outer,
                                 columns=("No", "IP", "MAC", "Status"),
                                 show="headings", style="S.Treeview")
        for col, txt, w, anch in [
            ("No",     "#",               55,  "center"),
            ("IP",     "IP ADDRESS",      170, "center"),
            ("MAC",    "MAC ADDRESS",     210, "center"),
            ("Status", "SECURITY STATUS", 430, "w"),
        ]:
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w, anchor=anch)

        self._sb = ttk.Scrollbar(self.table_outer, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self._sb.set)

        self._radar_angle = 0
        self._draw_radar(scanning=False)

    def _draw_radar(self, scanning=False):
        if not hasattr(self, 'radar_canvas'):
            return
        c = self.radar_canvas
        c.delete("all")
        cx, cy, R = 155, 118, 105

        c.create_oval(cx - R, cy - R, cx + R, cy + R,
                      fill="#0d1117", outline="#1e293b", width=1)
        for r in range(26, R + 1, 26):
            c.create_oval(cx - r, cy - r, cx + r, cy + r,
                          outline="#1e3a5f" if scanning else "#1a2744", width=1)
        for i in range(12):
            angle = math.radians(i * 30)
            xe = cx + R * math.cos(angle)
            ye = cy + R * math.sin(angle)
            c.create_line(cx, cy, xe, ye, fill="#1a2744", width=1)

        if scanning:
            for trail in range(7, 0, -1):
                trail_a = math.radians(self._radar_angle - trail * 7)
                colors = ["#6366f1","#5254cc","#4446aa","#363888","#282a66","#1a1c44","#0e1022"]
                tx = cx + R * math.cos(trail_a)
                ty = cy + R * math.sin(trail_a)
                c.create_line(cx, cy, tx, ty, fill=colors[7 - trail], width=3)
            sweep_a = math.radians(self._radar_angle)
            sx = cx + R * math.cos(sweep_a)
            sy = cy + R * math.sin(sweep_a)
            c.create_line(cx, cy, sx, sy, fill="#818cf8", width=2)
            blips = [(cx + 55, cy - 30), (cx - 40, cy + 60), (cx + 75, cy + 45)]
            for bx, by in blips:
                c.create_oval(bx - 4, by - 4, bx + 4, by + 4,
                              fill=GREEN, outline="", stipple="gray50")

        c.create_oval(cx - 5, cy - 5, cx + 5, cy + 5,
                      fill=GREEN if scanning else SUBTEXT, outline="")
        c.create_line(cx - R, cy, cx + R, cy, fill="#1a2744", width=1, dash=(3, 6))
        c.create_line(cx, cy - R, cx, cy + R, fill="#1a2744", width=1, dash=(3, 6))
        lbl = "● SCANNING..." if scanning else "○  RADAR IDLE"
        c.create_text(cx, cy + R + 16, text=lbl,
                      fill=GREEN if scanning else SUBTEXT, font=("Consolas", 10, "bold"))

        if scanning:
            self._radar_angle = (self._radar_angle + 5) % 360
            self._radar_job = self.after(35, lambda: self._draw_radar(scanning=True))

    def run_scan(self):
        self.empty_lbl.pack_forget()
        self.tree.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        self._sb.pack(side="right", fill="y")
        for i in self.tree.get_children():
            self.tree.delete(i)
        if self._radar_job:
            self.after_cancel(self._radar_job)
        self._radar_angle = 0
        self._draw_radar(scanning=True)

        def task():
            self.status_lbl.configure(text="● SCANNING...", text_color=YELLOW)
            self.scan_status_lbl.configure(text="Scanning 192.168.1.0/24 — please wait...")
            self.scan_count_lbl.configure(text="Active Devices: scanning...")

            devices = scan_network("192.168.1.0/24")
            save_devices(devices)

            self.threat_count = 0
            secure_count = 0
            self._all_scan_rows = []

            for i, d in enumerate(devices, 1):
                ports = scan_ports(d["ip"])
                danger_list = check_danger_ports(ports)
                if danger_list:
                    self.threat_count += 1
                    port_str    = ", ".join(map(str, danger_list))
                    status_text = f"🚨 DANGER — Ports: {port_str}"
                    tag = "danger"
                    # Email alert for dangerous device
                    self._send_email_alert(
                        subject=f"SENTINEL AI — Threat Detected: {d['ip']}",
                        body=(f"Dangerous device found on your network!\n\n"
                              f"IP     : {d['ip']}\n"
                              f"MAC    : {d['mac'].upper()}\n"
                              f"Ports  : {port_str}\n"
                              f"Time   : {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                              f"— SENTINEL AI")
                    )
                else:
                    secure_count += 1
                    status_text = "✔  SECURE"
                    tag = "safe"
                self._all_scan_rows.append((i, d["ip"], d["mac"].upper(), status_text, tag))
                self.tree.insert("", "end",
                                 values=(i, d["ip"], d["mac"].upper(), status_text),
                                 tags=(tag,))
                self.tree.tag_configure("danger", foreground=RED)
                self.tree.tag_configure("safe",   foreground=GREEN)
                self.scan_count_lbl.configure(text=f"Active Devices: {i}")
                time.sleep(0.18)

            self.device_count = len(devices)
            score_val, _ = self._calc_score()
            self.scan_count_lbl.configure(text=f"Active Devices: {self.device_count}")
            self.scan_threat_lbl.configure(text=f"Threats: {self.threat_count}")
            self.scan_secure_lbl.configure(text=f"Secure: {secure_count}")
            self.scan_status_lbl.configure(
                text=f"Scan complete — {self.device_count} devices | "
                     f"{self.threat_count} threats | Security Score: {score_val}")
            self.status_lbl.configure(text="● SCAN COMPLETE", text_color=GREEN)
            if self._radar_job:
                self.after_cancel(self._radar_job)
                self._radar_job = None
            self._draw_radar(scanning=False)

        threading.Thread(target=task, daemon=True).start()

    # =========================================================
    #  AI MONITOR PAGE
    # =========================================================
    def _build_ai_page(self, parent):
        self._page_header(parent, "🤖 AI Traffic Monitor",
                          "Machine learning anomaly detection — monitors for unusual network traffic")

        self.ai_canvas = ctk.CTkCanvas(parent, bg=BG, height=240, highlightthickness=0)
        self.ai_canvas.pack(fill="x", padx=30, pady=10)

        console_frame = ctk.CTkFrame(parent, fg_color=TABLE_BG, corner_radius=14)
        console_frame.pack(fill="both", expand=True, padx=30, pady=(0, 10))

        chdr = ctk.CTkFrame(console_frame, fg_color="#0f1629", corner_radius=0, height=40)
        chdr.pack(fill="x")
        chdr.pack_propagate(False)
        ctk.CTkLabel(chdr, text="● ● ●  SENTINEL AI ENGINE CONSOLE",
                     font=("Consolas", 11, "bold"), text_color=SUBTEXT).pack(side="left", padx=14, pady=10)

        self.ai_box = ctk.CTkTextbox(console_frame, font=("Consolas", 13),
                                     fg_color=TABLE_BG, text_color=GREEN,
                                     corner_radius=0, border_width=0)
        self.ai_box.pack(fill="both", expand=True, padx=4, pady=4)

        btn_row = ctk.CTkFrame(parent, fg_color="transparent")
        btn_row.pack(pady=12)

        ctk.CTkButton(btn_row, text="▶  START AI MONITOR",
                      command=self.start_ai,
                      fg_color=GREEN, hover_color="#059669",
                      text_color="white", font=("Segoe UI", 14, "bold"),
                      height=46, corner_radius=10, width=210).pack(side="left", padx=12)

        ctk.CTkButton(btn_row, text="⏹  STOP",
                      command=self.stop_ai,
                      fg_color=RED, hover_color="#dc2626",
                      font=("Segoe UI", 14, "bold"),
                      height=46, corner_radius=10, width=130).pack(side="left", padx=12)

        self._shield_phase = 0
        self._draw_shield(active=False)

    def _draw_shield(self, active=False, alert=False):
        if not hasattr(self, 'ai_canvas'):
            return
        c = self.ai_canvas
        c.delete("all")
        try:
            W = self.ai_canvas.winfo_width() or 900
        except Exception:
            W = 900
        H = 230
        cx, cy = W // 2, H // 2 + 10

        for i in range(20):
            sv = int(11 + i * 1.5)
            shade = f"#{sv:02x}{sv + 3:02x}{min(sv + 22, 42):02x}"
            c.create_oval(cx - i*18, cy - i*12, cx + i*18, cy + i*12, outline=shade, width=1)

        if active:
            for ring in range(3):
                offset = (self._shield_phase + ring * 30) % 90
                r_size = 50 + offset * 1.2
                alpha_idx = min(int(offset / 30), 2)
                ring_colors = ["#2d2f6b", "#1e2050", "#131535"]
                try:
                    c.create_oval(cx - r_size, cy - r_size * 0.7,
                                  cx + r_size, cy + r_size * 0.7,
                                  outline=ring_colors[alpha_idx], width=2)
                except Exception:
                    pass

        shield_color  = RED if alert else (GREEN if active else "#374151")
        shield_border = "#ef4444" if alert else (GREEN if active else "#4b5563")
        sw, sh = 70, 85
        sy_pt = cy - sh + 5
        shield_pts = [
            cx,       sy_pt - 10,
            cx + sw,  sy_pt,
            cx + sw,  sy_pt + sh * 0.6,
            cx,       sy_pt + sh + 10,
            cx - sw,  sy_pt + sh * 0.6,
            cx - sw,  sy_pt,
        ]
        c.create_polygon(shield_pts, fill=shield_color, outline=shield_border, width=3, smooth=True)

        text_color  = "#ef4444" if alert else (GREEN if active else SUBTEXT)
        shield_text = "ALERT!" if alert else ("MONITORING" if active else "IDLE")
        c.create_text(cx, cy - 10, text="🛡️", font=("Segoe UI", 28))
        c.create_text(cx, cy + 42, text=shield_text, fill=text_color, font=("Consolas", 13, "bold"))

        if active and not alert:
            for dot in range(6):
                angle = math.radians(self._shield_phase * 3 + dot * 60)
                dx = cx + 110 * math.cos(angle)
                dy = cy + 50 * math.sin(angle) * 0.6
                c.create_oval(dx - 5, dy - 5, dx + 5, dy + 5, fill=BLUE, outline="")

        status = ("AI MONITORING ACTIVE — Analyzing network traffic..." if active and not alert
                  else ("⚠ ANOMALY DETECTED — Unusual traffic spike!" if alert
                        else "Press START AI MONITOR to begin anomaly detection"))
        c.create_text(cx, H - 18, text=status, fill=text_color, font=("Consolas", 11))

        if active:
            self._shield_phase = (self._shield_phase + 1) % 360
            self._shield_job = self.after(50, lambda: self._draw_shield(active=True, alert=False))

    def _flash_alert(self, count=0):
        if not hasattr(self, 'ai_canvas'):
            return
        if count >= 6:
            self._draw_shield(active=True, alert=False)
            return
        self._draw_shield(active=False, alert=(count % 2 == 0))
        self._shield_job = self.after(300, lambda: self._flash_alert(count + 1))

    def start_ai(self):
        self.ai_running = True
        self.ai_box.delete("1.0", "end")
        self.ai_box.insert("end", ">>> SENTINEL AI Engine Initializing...\n")
        self.ai_box.insert("end", ">>> Collecting baseline traffic samples (10 seconds)...\n\n")
        if self._shield_job:
            self.after_cancel(self._shield_job)
        self._shield_phase = 0
        self._draw_shield(active=True)

        def task():
            self.status_lbl.configure(text="● AI TRAINING", text_color=YELLOW)
            data  = ai_anomaly.collect_data(10)
            model = ai_anomaly.train_model(data)
            self.ai_box.insert("end", "✅  Baseline established. Live monitoring active.\n")
            self.ai_box.insert("end", "─" * 52 + "\n\n")
            self.status_lbl.configure(text="● MONITORING", text_color=GREEN)

            prev = psutil.net_io_counters()
            while self.ai_running:
                time.sleep(2)
                curr = psutil.net_io_counters()
                traffic = (curr.bytes_recv - prev.bytes_recv +
                           curr.bytes_sent - prev.bytes_sent) / 1024
                self.live_traffic.configure(text=f"Traffic: {int(traffic)} KB/s")
                det, self.last_alert_time, _, _ = ai_anomaly.detect(
                    model, prev, curr, self.last_alert_time)
                if det:
                    self.alert_count += 1
                    msg = (f"🚨  ALERT [{time.strftime('%H:%M:%S')}]  Anomaly! "
                           f"Traffic spike: {int(traffic)} KB/s\n")
                    self.ai_box.insert("end", msg)
                    self.ai_box.see("end")
                    # Email alert
                    self._send_email_alert(
                        subject="SENTINEL AI — Traffic Anomaly Detected!",
                        body=(f"AI detected unusual network traffic!\n\n"
                              f"Traffic : {int(traffic)} KB/s\n"
                              f"Time    : {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                              f"— SENTINEL AI")
                    )
                    if self._shield_job:
                        self.after_cancel(self._shield_job)
                        self._shield_job = None
                    self.after(0, self._flash_alert)
                prev = curr

        threading.Thread(target=task, daemon=True).start()

    def stop_ai(self):
        self.ai_running = False
        if self._shield_job:
            self.after_cancel(self._shield_job)
            self._shield_job = None
        self._draw_shield(active=False)
        self.status_lbl.configure(text="● AI STOPPED", text_color=RED)
        self.live_traffic.configure(text="Traffic: 0 KB/s")
        self.ai_box.insert("end", "\n[!] Monitoring stopped manually.\n")

    # =========================================================
    #  DATABASE LOGS PAGE
    # =========================================================
    def _build_logs_page(self, parent):
        self._page_header(parent, "📂 Database Logs",
                          "All discovered devices stored in local SQLite database")

        self._logs_cards_area = ctk.CTkFrame(parent, fg_color="transparent")
        self._logs_cards_area.pack(fill="x", padx=30, pady=12)

        log_frame = ctk.CTkFrame(parent, fg_color=TABLE_BG, corner_radius=14)
        log_frame.pack(fill="both", expand=True, padx=30, pady=(0, 10))

        lhdr = ctk.CTkFrame(log_frame, fg_color="#0f1629", corner_radius=0, height=40)
        lhdr.pack(fill="x")
        lhdr.pack_propagate(False)
        ctk.CTkLabel(lhdr, text="● ● ●  DEVICE HISTORY DATABASE",
                     font=("Consolas", 11, "bold"), text_color=SUBTEXT).pack(side="left", padx=14, pady=10)

        self.log_box = ctk.CTkTextbox(log_frame, font=("Consolas", 12),
                                      fg_color=TABLE_BG, text_color=TEXT,
                                      corner_radius=0, border_width=0)
        self.log_box.pack(fill="both", expand=True, padx=4, pady=4)

        ctk.CTkButton(parent, text="🔄  REFRESH DATABASE",
                      command=self.load_logs,
                      fg_color=BLUE, hover_color="#4338ca",
                      font=("Segoe UI", 13, "bold"),
                      height=42, corner_radius=10).pack(pady=12)

    def load_logs(self):
        # Refresh summary cards
        for w in self._logs_cards_area.winfo_children():
            w.destroy()
        try:
            conn = sqlite3.connect("devices.db")
            rows = list(conn.execute("SELECT * FROM devices"))
            conn.close()
        except Exception:
            rows = []
        total     = len(rows)
        latest_ip = rows[-1][1] if rows else "—"
        db_cards = [
            ("🗄️", "Total Records",    str(total),    "Stored in devices.db",  CARD1),
            ("📡", "Latest Device IP", latest_ip,     "Most recently scanned", CARD2),
            ("🕐", "Last Updated",
             time.strftime("%H:%M") if rows else "—",
             "Database timestamp", CARD4),
        ]
        for col, (icon, title, value, sub, color) in enumerate(db_cards):
            self._mini_db_card(self._logs_cards_area, icon, title, value, sub, color, col)
            self._logs_cards_area.grid_columnconfigure(col, weight=1)

        # Refresh log text
        self.log_box.delete("1.0", "end")
        self.log_box.insert("end", f"{'─' * 62}\n")
        self.log_box.insert("end", "  SENTINEL AI — Device History Log\n")
        self.log_box.insert("end", f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_box.insert("end", f"{'─' * 62}\n\n")
        if not rows:
            self.log_box.insert("end", "  No records found. Run a Network Scan first.\n")
        else:
            for i, row in enumerate(rows, 1):
                mac      = row[0] if len(row) > 0 else "—"
                ip       = row[1] if len(row) > 1 else "—"
                lastseen = row[2] if len(row) > 2 else "—"
                self.log_box.insert(
                    "end",
                    f"  [{i:>3}]  IP: {ip:<18}  MAC: {mac:<20}  Last Seen: {lastseen}\n")
        self.log_box.insert("end", f"\n{'─' * 62}\n  Total Records: {len(rows)}\n")

    def _mini_db_card(self, parent, icon, title, value, sub, color, col):
        frame = ctk.CTkFrame(parent, fg_color=color, corner_radius=14, height=100)
        frame.grid(row=0, column=col, padx=7, sticky="nsew")
        frame.grid_propagate(False)
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(12, 0))
        ctk.CTkLabel(top, text=icon, font=("Segoe UI", 18)).pack(side="left")
        ctk.CTkLabel(frame, text=value,
                     font=("Segoe UI", 26, "bold"), text_color="white").pack(anchor="w", padx=14)
        ctk.CTkLabel(frame, text=title,
                     font=("Segoe UI", 11, "bold"), text_color="white").pack(anchor="w", padx=14)

    # =========================================================
    #  EMAIL ALERTS PAGE
    # =========================================================
    def _build_email_page(self, parent):
        self._page_header(parent, "📧 Email Alerts",
                          "Get instant Gmail alerts when threats or anomalies are detected")

        # Info box
        info = ctk.CTkFrame(parent, fg_color=CARD_BG, corner_radius=14)
        info.pack(fill="x", padx=30, pady=(12, 8))

        ctk.CTkLabel(info, text="⚙️  Gmail Setup Instructions",
                     font=("Segoe UI", 14, "bold"), text_color=TEXT).pack(anchor="w", padx=22, pady=(14, 6))
        steps = [
            ("1.", "Go to myaccount.google.com → Security → 2-Step Verification → Enable it"),
            ("2.", "Then go to: myaccount.google.com/apppasswords"),
            ("3.", "Create App Password → Select 'Mail' → Copy the 16-character password"),
            ("4.", "Paste your Gmail address and that App Password below"),
        ]
        for num, txt in steps:
            row = ctk.CTkFrame(info, fg_color="transparent")
            row.pack(fill="x", padx=22, pady=2)
            ctk.CTkLabel(row, text=num, font=("Segoe UI", 12, "bold"),
                         text_color=YELLOW, width=26).pack(side="left")
            ctk.CTkLabel(row, text=txt, font=("Segoe UI", 12),
                         text_color=SUBTEXT, wraplength=780, justify="left").pack(side="left")
        ctk.CTkFrame(info, height=1, fg_color="#1f2937").pack(fill="x", padx=22, pady=10)
        ctk.CTkLabel(info, text="⚠  Never share your App Password. It is stored only in memory — not saved to disk.",
                     font=("Segoe UI", 11), text_color=RED).pack(anchor="w", padx=22, pady=(0, 12))

        # Form
        form = ctk.CTkFrame(parent, fg_color=CARD_BG, corner_radius=14)
        form.pack(fill="x", padx=30, pady=8)

        ctk.CTkLabel(form, text="📬  Alert Configuration",
                     font=("Segoe UI", 14, "bold"), text_color=TEXT).pack(anchor="w", padx=22, pady=(14, 10))

        # Email field
        email_row = ctk.CTkFrame(form, fg_color="transparent")
        email_row.pack(fill="x", padx=22, pady=6)
        ctk.CTkLabel(email_row, text="Gmail Address:", font=("Segoe UI", 13),
                     text_color=TEXT, width=150, anchor="w").pack(side="left")
        self._email_entry = ctk.CTkEntry(email_row,
                                         placeholder_text="yourname@gmail.com",
                                         fg_color="#1f2937", border_color=BLUE,
                                         text_color=TEXT, font=("Segoe UI", 13),
                                         width=340, height=38)
        self._email_entry.pack(side="left", padx=(0, 10))

        # Password field
        pass_row = ctk.CTkFrame(form, fg_color="transparent")
        pass_row.pack(fill="x", padx=22, pady=6)
        ctk.CTkLabel(pass_row, text="App Password:", font=("Segoe UI", 13),
                     text_color=TEXT, width=150, anchor="w").pack(side="left")
        self._pass_entry = ctk.CTkEntry(pass_row,
                                        placeholder_text="16-character App Password",
                                        show="●",
                                        fg_color="#1f2937", border_color=BLUE,
                                        text_color=TEXT, font=("Segoe UI", 13),
                                        width=340, height=38)
        self._pass_entry.pack(side="left", padx=(0, 10))

        # Buttons
        btn_row = ctk.CTkFrame(form, fg_color="transparent")
        btn_row.pack(fill="x", padx=22, pady=(10, 18))

        ctk.CTkButton(btn_row, text="✅  SAVE & ENABLE",
                      command=self._save_email_settings,
                      fg_color=GREEN, hover_color="#059669",
                      font=("Segoe UI", 13, "bold"), height=42,
                      corner_radius=10, width=180).pack(side="left", padx=(0, 12))

        ctk.CTkButton(btn_row, text="🧪  SEND TEST EMAIL",
                      command=self._send_test_email,
                      fg_color=BLUE, hover_color="#4338ca",
                      font=("Segoe UI", 13, "bold"), height=42,
                      corner_radius=10, width=180).pack(side="left", padx=(0, 12))

        ctk.CTkButton(btn_row, text="🚫  DISABLE",
                      command=self._disable_email,
                      fg_color="transparent", border_width=2, border_color=RED,
                      hover_color="#1f2937", text_color=RED,
                      font=("Segoe UI", 13, "bold"), height=42,
                      corner_radius=10, width=130).pack(side="left")

        # Status label
        self._email_form_status = ctk.CTkLabel(form, text="",
                                               font=("Segoe UI", 12), text_color=SUBTEXT)
        self._email_form_status.pack(anchor="w", padx=22, pady=(0, 10))

        # Alert log
        log_outer = ctk.CTkFrame(parent, fg_color=TABLE_BG, corner_radius=14)
        log_outer.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        lhdr = ctk.CTkFrame(log_outer, fg_color="#0f1629", corner_radius=0, height=40)
        lhdr.pack(fill="x")
        lhdr.pack_propagate(False)
        ctk.CTkLabel(lhdr, text="● ● ●  EMAIL ALERT LOG",
                     font=("Consolas", 11, "bold"), text_color=SUBTEXT).pack(side="left", padx=14, pady=10)

        self.email_log_box = ctk.CTkTextbox(log_outer, font=("Consolas", 12),
                                            fg_color=TABLE_BG, text_color=GREEN,
                                            corner_radius=0, border_width=0)
        self.email_log_box.pack(fill="both", expand=True, padx=4, pady=4)
        self.email_log_box.insert("end", "  Email alert log will appear here...\n")

    def _save_email_settings(self):
        email = self._email_entry.get().strip()
        password = self._pass_entry.get().strip()

        if not email or "@gmail.com" not in email:
            self._email_form_status.configure(
                text="❌  Please enter a valid Gmail address.", text_color=RED)
            return
        if len(password) < 8:
            self._email_form_status.configure(
                text="❌  App Password too short. Use the 16-char Google App Password.", text_color=RED)
            return

        self._alert_email    = email
        self._alert_password = password
        self._email_enabled  = True
        self.email_status_lbl.configure(text="📧 Email: ON", text_color=GREEN)
        self._email_form_status.configure(
            text=f"✅  Email alerts enabled for {email}", text_color=GREEN)
        self._log_email_event(f"✅  Alerts enabled → {email}")

    def _disable_email(self):
        self._email_enabled  = False
        self._alert_email    = ""
        self._alert_password = ""
        self.email_status_lbl.configure(text="📧 Email: OFF", text_color=SUBTEXT)
        self._email_form_status.configure(text="🚫  Email alerts disabled.", text_color=SUBTEXT)
        self._log_email_event("🚫  Email alerts disabled.")

    def _send_test_email(self):
        if not self._email_enabled:
            self._email_form_status.configure(
                text="⚠  Save & Enable email first, then test.", text_color=YELLOW)
            return
        self._email_form_status.configure(text="📤  Sending test email...", text_color=YELLOW)
        self._send_email_alert(
            subject="SENTINEL AI — Test Alert ✅",
            body=(f"This is a test alert from SENTINEL AI.\n\n"
                  f"If you received this, email alerts are working correctly!\n\n"
                  f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                  f"— SENTINEL AI")
        )
        self.after(2000, lambda: self._email_form_status.configure(
            text="✅  Test email sent! Check your inbox.", text_color=GREEN))
        self._log_email_event("📤  Test email sent.")

    def _log_email_event(self, msg):
        """Append to email alert log box."""
        ts = time.strftime("%H:%M:%S")
        try:
            self.email_log_box.insert("end", f"  [{ts}]  {msg}\n")
            self.email_log_box.see("end")
        except Exception:
            pass

    # Override _send_email_alert to also log to email_log_box
    def _send_email_alert(self, subject, body):
        if not self._email_enabled or not self._alert_email or not self._alert_password:
            return

        self._log_email_event(f"📤  Sending: {subject}")

        def _send():
            try:
                msg = MIMEMultipart()
                msg["From"]    = self._alert_email
                msg["To"]      = self._alert_email
                msg["Subject"] = subject
                msg.attach(MIMEText(body, "plain"))
                with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
                    server.login(self._alert_email, self._alert_password)
                    server.sendmail(self._alert_email, self._alert_email, msg.as_string())
                self.after(0, lambda: self._log_email_event(f"✅  Sent: {subject}"))
            except Exception as e:
                self.after(0, lambda: self._log_email_event(f"❌  Failed: {e}"))

        threading.Thread(target=_send, daemon=True).start()

    # =========================================================
    #  EXPORT CSV
    # =========================================================
    def export_to_file(self):
        if not hasattr(self, 'tree') or not self.tree.get_children():
            messagebox.showwarning("No Data", "Pehle Network Scan karein, phir export karein!")
            return
        filename = f"Sentinel_Report_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, "w", newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "IP ADDRESS", "MAC ADDRESS", "SECURITY STATUS"])
                for item in self.tree.get_children():
                    writer.writerow(self.tree.item(item)['values'])
            messagebox.showinfo("Exported ✅", f"Report saved:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Save nahi ho saka:\n{e}")


if __name__ == "__main__":
    app = NetworkGUI()
    app.mainloop()