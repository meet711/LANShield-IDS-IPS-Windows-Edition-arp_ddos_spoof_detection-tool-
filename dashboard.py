"""
dashboard.py  –  Flask Web Dashboard for LAN IDS (Windows Edition)
=============================================================================
Accessible at  http://127.0.0.1:5000  (or the machine's LAN IP)

Layout
──────
• TOP    — ARP Spoof Detection panel  (events from local sniff)
• BOTTOM — DDoS Victim Alerts panel   (HTTP POSTs from victim machines
                                        running victim_ddos_detector.py)
• Right sidebar — Currently Blocked IPs + Attack cheat-sheet

Victim machines POST to  POST /alert  with JSON:
  {
    "attacker_ip":  "...",
    "victim_ip":    "...",
    "attack_type":  "TCP SYN FLOOD",
    "packet_count": 1500,
    "timestamp":    "2026-04-20 14:32:01"
  }
"""

import threading
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request as flask_request
from logger import get_recent_events
from config import Config

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────
#  In-memory store for DDoS victim alerts
#  (keyed by victim_ip so the panel shows per-machine status)
# ─────────────────────────────────────────────────────────────────
_ddos_alerts: deque = deque(maxlen=200)   # newest first order maintained on insert
_ddos_lock   = threading.Lock()


# ─────────────────────────────────────────────────────────────────
#  /alert  – victim machines POST here
# ─────────────────────────────────────────────────────────────────
@app.route("/alert", methods=["POST"])
def receive_alert():
    data = flask_request.get_json(silent=True) or {}
    entry = {
        "timestamp":    data.get("timestamp",    datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "victim_ip":    data.get("victim_ip",    "unknown"),
        "attacker_ip":  data.get("attacker_ip",  "unknown"),
        "attack_type":  data.get("attack_type",  "UNKNOWN"),
        "packet_count": data.get("packet_count", 0),
    }
    with _ddos_lock:
        _ddos_alerts.appendleft(entry)   # newest at front
    return jsonify({"status": "ok"}), 200


# ─────────────────────────────────────────────────────────────────
#  HTML template
# ─────────────────────────────────────────────────────────────────
_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>LAN-Shield IDS — Intrusion Detection System</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base:       #080c12;
      --bg-panel:      #0d1117;
      --bg-card:       #111820;
      --bg-card2:      #141c26;
      --border:        #1e2a3a;
      --border-glow:   #1e3a5a;
      --accent-blue:   #38bdf8;
      --accent-cyan:   #22d3ee;
      --accent-green:  #4ade80;
      --accent-red:    #f87171;
      --accent-amber:  #fbbf24;
      --accent-purple: #a78bfa;
      --text-primary:  #e2e8f0;
      --text-secondary:#94a3b8;
      --text-muted:    #475569;
      --arp-color:     #f87171;
      --arp-glow:      #f8717133;
      --ddos-color:    #fbbf24;
      --ddos-glow:     #fbbf2433;
      --green-glow:    #4ade8033;
      --blue-glow:     #38bdf833;
      --font-mono:     'JetBrains Mono', 'Courier New', monospace;
      --font-sans:     'Inter', system-ui, sans-serif;
      --radius:        10px;
      --radius-sm:     6px;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--font-sans);
      background: var(--bg-base);
      color: var(--text-primary);
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* ── Animated background grid ──────────────────────────────── */
    body::before {
      content: '';
      position: fixed; inset: 0;
      background-image:
        linear-gradient(rgba(56,189,248,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(56,189,248,.03) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none; z-index: 0;
    }

    /* ── Header ─────────────────────────────────────────────────── */
    header {
      position: sticky; top: 0; z-index: 200;
      background: rgba(8,12,18,.92);
      backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--border);
      padding: 0 24px;
      height: 60px;
      display: flex; align-items: center; gap: 16px;
    }
    .header-logo {
      display: flex; align-items: center; gap: 10px;
    }
    .logo-icon {
      width: 36px; height: 36px;
      background: linear-gradient(135deg, #1e3a5a, #0d1f36);
      border: 1px solid var(--accent-blue);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 18px;
      box-shadow: 0 0 16px var(--blue-glow);
      flex-shrink: 0;
    }
    .logo-text h1 {
      font-size: 1.1rem; font-weight: 700; letter-spacing: .5px;
      background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan));
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .logo-text .sub {
      font-size: .68rem; color: var(--text-muted); letter-spacing: 1.5px;
      text-transform: uppercase; font-weight: 500;
    }
    .header-badges { display: flex; gap: 8px; }
    .hbadge {
      font-size: .65rem; font-weight: 600; letter-spacing: .8px;
      text-transform: uppercase; padding: 3px 10px; border-radius: 20px;
    }
    .hbadge.win  { background: #0f2847; color: var(--accent-blue);  border: 1px solid #1e3a5a; }
    .hbadge.live { background: #0a251a; color: var(--accent-green); border: 1px solid #1a4a2a; }
    .live-dot {
      display: inline-block; width: 6px; height: 6px; border-radius: 50%;
      background: var(--accent-green); margin-right: 4px;
      animation: pulse-dot 1.5s ease-in-out infinite;
    }
    @keyframes pulse-dot {
      0%,100% { opacity:1; box-shadow: 0 0 0 0 var(--green-glow); }
      50%      { opacity:.6; box-shadow: 0 0 0 6px transparent; }
    }
    #clock {
      margin-left: auto; font-family: var(--font-mono);
      font-size: .82rem; color: var(--text-muted); letter-spacing: 1px;
    }

    /* ── Layout wrapper ─────────────────────────────────────────── */
    .layout {
      position: relative; z-index: 1;
      display: grid;
      grid-template-columns: 1fr 380px;
      grid-template-rows: auto auto auto;
      gap: 0;
      padding: 0;
    }

    /* ── Stats bar ──────────────────────────────────────────────── */
    .stats-bar {
      grid-column: 1 / -1;
      display: flex; gap: 1px;
      background: var(--border);
      border-bottom: 1px solid var(--border);
    }
    .stat-chip {
      flex: 1; padding: 14px 20px;
      background: var(--bg-panel);
      display: flex; flex-direction: column; align-items: center;
      position: relative; overflow: hidden;
      transition: background .2s;
    }
    .stat-chip::after {
      content: ''; position: absolute; bottom: 0; left: 0; right: 0;
      height: 2px;
    }
    .stat-chip.arp-chip::after   { background: var(--arp-color); }
    .stat-chip.ddos-chip::after  { background: var(--ddos-color); }
    .stat-chip.block-chip::after { background: var(--accent-blue); }
    .stat-chip.victims-chip::after { background: var(--accent-purple); }
    .stat-chip.total-chip::after { background: var(--accent-green); }
    .stat-chip.fired-chip::after { background: var(--accent-cyan); }
    .stat-chip:hover { background: var(--bg-card); }
    .stat-num {
      font-family: var(--font-mono); font-size: 1.8rem; font-weight: 700;
      line-height: 1;
    }
    .stat-chip.arp-chip   .stat-num { color: var(--arp-color); }
    .stat-chip.ddos-chip  .stat-num { color: var(--ddos-color); }
    .stat-chip.block-chip .stat-num { color: var(--accent-blue); }
    .stat-chip.victims-chip .stat-num { color: var(--accent-purple); }
    .stat-chip.total-chip .stat-num { color: var(--accent-green); }
    .stat-chip.fired-chip .stat-num { color: var(--accent-cyan); }
    .stat-lbl {
      font-size: .6rem; color: var(--text-muted); margin-top: 4px;
      text-transform: uppercase; letter-spacing: 1px; font-weight: 600;
      text-align: center;
    }

    /* ── Main content area ──────────────────────────────────────── */
    .main-col {
      grid-column: 1;
      display: flex; flex-direction: column;
      border-right: 1px solid var(--border);
    }

    /* ── Panel (ARP / DDoS) ─────────────────────────────────────── */
    .panel {
      display: flex; flex-direction: column;
      border-bottom: 1px solid var(--border);
    }
    .panel:last-child { border-bottom: none; }

    .panel-header {
      display: flex; align-items: center; gap: 12px;
      padding: 14px 20px 12px;
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
    }
    .panel-icon {
      width: 32px; height: 32px; border-radius: var(--radius-sm);
      display: flex; align-items: center; justify-content: center;
      font-size: 15px; flex-shrink: 0;
    }
    .panel-arp  .panel-icon { background: #2a0f0f; border: 1px solid #5a1f1f; box-shadow: 0 0 12px var(--arp-glow); }
    .panel-ddos .panel-icon { background: #2a1f00; border: 1px solid #5a4000; box-shadow: 0 0 12px var(--ddos-glow); }
    .panel-title { font-size: .95rem; font-weight: 600; }
    .panel-arp  .panel-title { color: var(--arp-color); }
    .panel-ddos .panel-title { color: var(--ddos-color); }
    .panel-subtitle { font-size: .7rem; color: var(--text-muted); margin-top: 1px; }
    .panel-header-right { margin-left: auto; display: flex; align-items: center; gap: 8px; }

    /* ── Toolbar ─────────────────────────────────────────────────── */
    .toolbar {
      display: flex; gap: 6px; align-items: center; flex-wrap: wrap;
      padding: 10px 20px;
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
    }
    .toolbar input[type=text] {
      flex: 1; min-width: 140px;
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: var(--radius-sm); color: var(--text-primary);
      padding: 6px 12px; font-family: var(--font-mono); font-size: .78rem;
      outline: none; transition: border-color .2s;
    }
    .toolbar input[type=text]::placeholder { color: var(--text-muted); }
    .toolbar input[type=text]:focus { border-color: var(--accent-blue); }

    .tbtn {
      border: 1px solid var(--border); border-radius: var(--radius-sm);
      padding: 6px 12px; font-size: .72rem; font-family: var(--font-sans);
      font-weight: 500; cursor: pointer; white-space: nowrap;
      transition: all .15s; background: var(--bg-card);
      color: var(--text-secondary);
    }
    .tbtn:hover { border-color: #334155; color: var(--text-primary); background: var(--bg-card2); }

    /* Filter buttons */
    .tbtn.filt-arp.active  { background:#2a0f0f; color:var(--arp-color);  border-color:#5a1f1f; }
    .tbtn.filt-ddos.active { background:#2a1f00; color:var(--ddos-color); border-color:#5a4000; }
    .tbtn.filt-blue.active { background:#0f1f2a; color:var(--accent-blue); border-color:#1e3a5a; }
    .tbtn.filt-gray.active { background:#1a1a2a; color:#a78bfa; border-color:#2a2a4a; }

    /* Pause/clear */
    .tbtn.paused { background:#2a0f0f; color:var(--arp-color); border-color:#5a1f1f; }

    /* ── Victim pills ─────────────────────────────────────────────── */
    .victim-strip {
      display: flex; flex-wrap: wrap; gap: 6px; align-items: center;
      padding: 8px 20px;
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
    }
    .vpill {
      font-size: .68rem; font-weight: 600; font-family: var(--font-mono);
      padding: 3px 10px; border-radius: 20px; cursor: pointer;
      border: 1px solid var(--border); color: var(--text-muted);
      background: var(--bg-card); transition: all .15s;
    }
    .vpill:hover { border-color: #fbbf2455; color: var(--ddos-color); }
    .vpill.active { background:#2a1f00; color:var(--ddos-color); border-color:#5a4000; }

    /* ── Log table area ───────────────────────────────────────────── */
    .log-area {
      flex: 1; overflow-y: auto; overflow-x: hidden;
      height: 480px;          /* fixed height — both panels get equal space */
    }
    .log-area::-webkit-scrollbar { width: 6px; }
    .log-area::-webkit-scrollbar-track { background: var(--bg-base); }
    .log-area::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
    .log-area::-webkit-scrollbar-thumb:hover { background: #334155; }

    table { width: 100%; border-collapse: collapse; }
    thead th {
      position: sticky; top: 0; z-index: 5;
      background: var(--bg-card);
      color: var(--text-muted); font-size: .65rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: .8px;
      padding: 8px 14px; text-align: left;
      border-bottom: 1px solid var(--border);
    }
    tbody td {
      padding: 8px 14px; border-bottom: 1px solid rgba(30,42,58,.6);
      font-size: .8rem; font-family: var(--font-mono);
      vertical-align: middle;
    }
    tbody tr { transition: background .1s; }
    tbody tr:hover td { background: rgba(30,42,58,.5); }

    /* Specific td colors */
    .td-ts    { color: var(--text-muted); white-space: nowrap; font-size: .72rem; }
    .td-ip    { color: var(--accent-blue); white-space: nowrap; }
    .td-atk   { color: var(--arp-color); white-space: nowrap; }
    .td-victim{ color: var(--arp-color); font-weight: 600; }
    .td-attacker { color: var(--ddos-color); }
    .td-pkt   { color: var(--accent-purple); }
    .td-msg   { color: var(--text-secondary); word-break: break-word; white-space: normal; }

    .empty-row td { color: var(--text-muted); text-align: center; padding: 32px; font-size: .82rem; font-family: var(--font-sans); }

    /* ── Event type badges ───────────────────────────────────────── */
    .badge-type {
      display: inline-block; padding: 2px 8px; border-radius: 4px;
      font-size: .65rem; font-weight: 700; letter-spacing: .5px;
      text-transform: uppercase; white-space: nowrap;
      font-family: var(--font-sans);
    }
    .badge-ARP_SPOOF { background:#3d0a0a; color:#f87171; border: 1px solid #7a1515; }
    .badge-BLOCK     { background:#0a1a3d; color:#38bdf8; border: 1px solid #1a3a7a; }
    .badge-UNBLOCK   { background:#0a3d1a; color:#4ade80; border: 1px solid #1a7a3a; }
    .badge-SYSTEM    { background:#1a1a2e; color:#a78bfa; border: 1px solid #3a2a6e; }
    .badge-ddos      { background:#3d2800; color:#fbbf24; border: 1px solid #7a5000; }

    /* Log footer bar */
    .log-footer {
      display: flex; align-items: center; gap: 10px;
      padding: 8px 20px; background: var(--bg-panel);
      border-top: 1px solid var(--border); flex-shrink: 0;
    }
    .log-footer .row-count { font-size: .68rem; color: var(--text-muted); font-family: var(--font-mono); }
    .log-footer button {
      font-size: .7rem; padding: 4px 12px; border-radius: var(--radius-sm);
      border: 1px solid var(--border); background: var(--bg-card);
      color: var(--text-muted); cursor: pointer; font-family: var(--font-sans);
      transition: all .15s;
    }
    .log-footer button:hover { border-color: #334155; color: var(--text-secondary); }

    /* ── Right sidebar ───────────────────────────────────────────── */
    .sidebar {
      grid-column: 2;
      grid-row: 2 / 4;
      display: flex; flex-direction: column;
      background: var(--bg-panel);
      overflow-y: auto;
      border-left: 1px solid var(--border);
    }
    .sidebar::-webkit-scrollbar { width: 5px; }
    .sidebar::-webkit-scrollbar-thumb { background: var(--border); }

    .side-section {
      padding: 18px;
      border-bottom: 1px solid var(--border);
    }
    .side-title {
      font-size: .7rem; font-weight: 700; letter-spacing: 1.2px;
      text-transform: uppercase; margin-bottom: 14px;
      display: flex; align-items: center; gap: 8px;
    }
    .side-title-arp  { color: var(--arp-color); }
    .side-title-green{ color: var(--accent-green); }
    .side-title-blue { color: var(--accent-blue); }
    .side-icon { font-size: 14px; }

    /* Blocked IPs list & Unblocking */
    #blocked-list { list-style: none; }
    #blocked-list li {
      padding: 8px 0; border-bottom: 1px solid var(--border);
      font-size: .78rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    #blocked-list li:last-child { border-bottom: none; }
    .bl-ip { color: var(--arp-color); font-family: var(--font-mono); font-weight: 600; display: block; }
    .bl-ts { color: var(--text-muted); font-size: .65rem; font-family: var(--font-mono); }
    .bl-none { color: var(--text-muted); font-size: .8rem; }
    .tbtn-unblock {
      background: transparent; border: none; color: var(--accent-red);
      font-size: .9rem; font-weight: bold; cursor: pointer; padding: 4px 8px;
      border-radius: 4px; transition: all .15s;
    }
    .tbtn-unblock:hover { background: rgba(248, 113, 113, 0.15); color: #ef4444; }

    /* Cheat sheet & commands */
    .cheat-content {
      max-height: 1000px;
      transition: max-height 0.3s ease-out, opacity 0.2s;
      overflow: hidden;
    }
    .cheat-content.collapsed {
      max-height: 0;
      opacity: 0;
      pointer-events: none;
    }
    .cheat-entry {
      margin-bottom: 10px; padding: 10px;
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: var(--radius-sm);
    }
    .cheat-label { font-size: .65rem; color: var(--text-primary); font-weight: 600; text-transform: uppercase; letter-spacing: .8px; margin-bottom: 2px; }
    .cheat-desc { font-size: .65rem; color: var(--text-secondary); margin-bottom: 6px; }
    .cheat-cmd { font-family: var(--font-mono); font-size: .72rem; color: var(--accent-cyan); word-break: break-all; background: rgba(8,12,18,.5); padding: 4px 6px; border-radius: 4px; display: block; border: 1px solid var(--border); }

    /* Security status card */
    .security-status-card {
      background: rgba(17, 24, 32, 0.4);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 14px 16px;
      display: flex;
      align-items: center;
      gap: 16px;
      position: relative;
      overflow: hidden;
      transition: all 0.3s ease;
      box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    }
    .security-status-card::before {
      content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 4px;
      background: var(--accent-green); transition: background 0.3s;
    }
    .security-status-card.status-warning::before { background: var(--accent-amber); }
    .security-status-card.status-critical::before { background: var(--accent-red); }
    
    .pulse-indicator-wrapper {
      position: relative; width: 24px; height: 24px; flex-shrink: 0;
    }
    .status-pulse-circle {
      width: 12px; height: 12px; border-radius: 50%;
      background: var(--accent-green);
      position: absolute; top: 6px; left: 6px; z-index: 2;
      transition: background 0.3s;
    }
    .status-pulse-ring {
      width: 24px; height: 24px; border-radius: 50%;
      border: 2px solid var(--accent-green);
      position: absolute; top: 0; left: 0; z-index: 1;
      animation: pulse-ring-anim 1.8s cubic-bezier(0.24, 0, 0.38, 1) infinite;
      opacity: 0.8;
      transition: border-color 0.3s;
    }
    .security-status-card.status-warning .status-pulse-circle { background: var(--accent-amber); }
    .security-status-card.status-warning .status-pulse-ring { border-color: var(--accent-amber); }
    .security-status-card.status-critical .status-pulse-circle { background: var(--accent-red); }
    .security-status-card.status-critical .status-pulse-ring { border-color: var(--accent-red); }

    @keyframes pulse-ring-anim {
      0% { transform: scale(0.6); opacity: 1; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .status-text-details { display: flex; flex-direction: column; }
    .status-title {
      font-size: .95rem; font-weight: 700; letter-spacing: 1px;
      color: var(--accent-green); transition: color 0.3s;
    }
    .status-desc { font-size: .7rem; color: var(--text-secondary); margin-top: 2px; }
    .security-status-card.status-warning .status-title { color: var(--accent-amber); }
    .security-status-card.status-critical .status-title { color: var(--accent-red); }

    /* System Environment Card */
    .system-info-grid {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .info-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: .74rem;
      border-bottom: 1px dashed rgba(30,42,58,.4);
      padding-bottom: 6px;
    }
    .info-item:last-child {
      border-bottom: none; padding-bottom: 0;
    }
    .info-label { color: var(--text-secondary); font-weight: 500; }
    .info-val { font-family: var(--font-mono); color: var(--text-primary); text-align: right; }
    .info-val.status-live-text { color: var(--accent-green); font-weight: bold; }
    .info-val.interface-desc-scroll {
      max-width: 220px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    /* Firewall Control */
    .manual-block-form {
      display: flex; gap: 6px; margin-bottom: 12px;
    }
    .manual-block-form input[type=text] {
      flex: 1; background: var(--bg-card); border: 1px solid var(--border);
      border-radius: var(--radius-sm); color: var(--text-primary);
      padding: 6px 10px; font-family: var(--font-mono); font-size: .75rem;
      outline: none; transition: border-color .2s;
    }
    .manual-block-form input[type=text]:focus { border-color: var(--arp-color); }
    .unblock-all-wrapper { margin-bottom: 14px; }

    /* Baseline Mapping Table */
    .baseline-search-wrapper { margin-bottom: 8px; }
    .baseline-search-wrapper input {
      width: 100%; background: var(--bg-card); border: 1px solid var(--border);
      border-radius: var(--radius-sm); color: var(--text-primary);
      padding: 6px 10px; font-family: var(--font-mono); font-size: .75rem;
      outline: none;
    }
    .baseline-search-wrapper input:focus { border-color: var(--accent-green); }
    .baseline-table-container {
      max-height: 180px; overflow-y: auto; border: 1px solid var(--border); border-radius: var(--radius-sm);
    }
    .baseline-table-container::-webkit-scrollbar { width: 4px; }
    .baseline-table-container::-webkit-scrollbar-thumb { background: var(--border); }
    .baseline-table { width: 100%; border-collapse: collapse; }
    .baseline-table th {
      background: var(--bg-card2); color: var(--text-muted); font-size: .6rem;
      text-transform: uppercase; font-weight: 600; padding: 6px 10px; border-bottom: 1px solid var(--border);
    }
    .baseline-table td {
      padding: 6px 10px; border-bottom: 1px solid rgba(30,42,58,.3); font-size: .72rem; font-family: var(--font-mono);
    }
    .baseline-table tr:hover td { background: rgba(56,189,248,.03); }

    footer {
      grid-column: 1 / -1;
      text-align: center; color: var(--text-muted);
      font-size: .65rem; padding: 14px;
      border-top: 1px solid var(--border);
      letter-spacing: .5px;
    }
  </style>
</head>
<body>

<!-- ── Header ───────────────────────────────────────────────────── -->
<header>
  <div class="header-logo">
    <div class="logo-icon">🛡</div>
    <div class="logo-text">
      <h1>LAN-Shield IDS/IPS</h1>
      <div class="sub">Intrusion Detection System</div>
    </div>
  </div>
  <div class="header-badges">
    <span class="hbadge live"><span class="live-dot"></span>Live</span>
  </div>
  <span id="clock"></span>
</header>

<!-- ── Layout ───────────────────────────────────────────────────── -->
<div class="layout">

  <!-- ── Stats bar ─────────────────────────────────────────────── -->
  <div class="stats-bar">
    <div class="stat-chip arp-chip">
      <div class="stat-num" id="s-arp">—</div>
      <div class="stat-lbl">ARP Events</div>
    </div>
    <div class="stat-chip ddos-chip">
      <div class="stat-num" id="s-ddos">—</div>
      <div class="stat-lbl">DDoS Alerts</div>
    </div>
    <div class="stat-chip victims-chip">
      <div class="stat-num" id="s-victims">—</div>
      <div class="stat-lbl">Victims Reporting</div>
    </div>
    <div class="stat-chip fired-chip">
      <div class="stat-num" id="s-block">—</div>
      <div class="stat-lbl">Blocks Fired</div>
    </div>
    <div class="stat-chip block-chip">
      <div class="stat-num" id="s-blocked">—</div>
      <div class="stat-lbl">Currently Blocked</div>
    </div>
    <div class="stat-chip total-chip">
      <div class="stat-num" id="s-total">—</div>
      <div class="stat-lbl">Total Events</div>
    </div>
  </div>

  <!-- ── Main column ───────────────────────────────────────────── -->
  <div class="main-col">

    <!-- ════ ARP PANEL ════ -->
    <div class="panel panel-arp">
      <div class="panel-header">
        <div class="panel-icon">🔴</div>
        <div>
          <div class="panel-title">ARP Spoof Detection</div>
          <div class="panel-subtitle">Local network sniff · auto-refresh 3s</div>
        </div>
        <div class="panel-header-right">
          <span id="arp-status-badge" style="font-size:.65rem;color:var(--accent-green);font-weight:600;letter-spacing:.8px;text-transform:uppercase;">● Monitoring</span>
        </div>
      </div>

      <div class="toolbar">
        <button class="tbtn filt-arp active" data-panel="arp" data-filter="ALL">All</button>
        <button class="tbtn filt-arp"        data-panel="arp" data-filter="ARP_SPOOF">ARP Spoof</button>
        <button class="tbtn filt-blue"       data-panel="arp" data-filter="BLOCK">Block</button>
        <button class="tbtn filt-gray"       data-panel="arp" data-filter="SYSTEM">System</button>
        <input type="text" id="arp-search" placeholder="🔍  Filter by IP or message…">
        <button class="tbtn" id="pause-arp">⏸ Pause</button>
        <button class="tbtn" id="clear-arp">✕ Clear</button>
      </div>

      <div class="log-area" id="arp-wrapper">
        <table>
          <thead>
            <tr>
              <th style="width:140px">Timestamp</th>
              <th style="width:110px">Type</th>
              <th style="width:130px">Source IP</th>
              <th>Detail / Message</th>
            </tr>
          </thead>
          <tbody id="arp-tbody">
            <tr class="empty-row"><td colspan="4">Waiting for ARP events…</td></tr>
          </tbody>
        </table>
      </div>

      <div class="log-footer">
        <button id="arp-load-more">Load 200 events</button>
        <span class="row-count" id="arp-row-count"></span>
      </div>
    </div><!-- /ARP PANEL -->

    <!-- ════ DDoS PANEL ════ -->
    <div class="panel panel-ddos">
      <div class="panel-header">
        <div class="panel-icon">🟡</div>
        <div>
          <div class="panel-title">DDoS Victim Alerts</div>
          <div class="panel-subtitle">Reported by victim machines · auto-refresh 3s</div>
        </div>
        <div class="panel-header-right">
          <span id="ddos-status-badge" style="font-size:.65rem;color:var(--accent-amber);font-weight:600;letter-spacing:.8px;text-transform:uppercase;">● Listening</span>
        </div>
      </div>

      <!-- Per-victim filter pills -->
      <div class="victim-strip" id="victim-pills">
        <span class="vpill active" data-victim="ALL">All Victims</span>
      </div>

      <div class="toolbar">
        <input type="text" id="ddos-search" placeholder="🔍  Filter by IP, attack type…">
        <button class="tbtn" id="pause-ddos">⏸ Pause</button>
        <button class="tbtn" id="clear-ddos">✕ Clear</button>
      </div>

      <div class="log-area" id="ddos-wrapper">
        <table>
          <thead>
            <tr>
              <th style="width:140px">Timestamp</th>
              <th style="width:130px">Victim IP</th>
              <th style="width:130px">Attacker IP</th>
              <th style="width:140px">Attack Type</th>
              <th>Packets</th>
            </tr>
          </thead>
          <tbody id="ddos-tbody">
            <tr class="empty-row"><td colspan="5">No DDoS alerts received yet…</td></tr>
          </tbody>
        </table>
      </div>

      <div class="log-footer">
        <span class="row-count" id="ddos-row-count"></span>
      </div>
    </div><!-- /DDoS PANEL -->

  </div><!-- /main-col -->

  <!-- ── Right sidebar ─────────────────────────────────────────── -->
  <div class="sidebar">
    <!-- Section 1: Security Status Widget -->
    <div class="side-section">
      <div class="side-title"><span class="side-icon">🛡️</span>Network Security Status</div>
      <div class="security-status-card" id="security-card">
        <div class="pulse-indicator-wrapper">
          <div class="status-pulse-circle" id="status-pulse"></div>
          <div class="status-pulse-ring" id="status-ring"></div>
        </div>
        <div class="status-text-details">
          <div class="status-title" id="security-status-title">SECURE</div>
          <div class="status-desc" id="security-status-desc">All systems operating normally.</div>
        </div>
      </div>
    </div>

    <!-- Section 2: System Environment Card -->
    <div class="side-section">
      <div class="side-title"><span class="side-icon">💻</span>System Environment</div>
      <div class="system-info-grid">
        <div class="info-item">
          <span class="info-label">Host IP</span>
          <span class="info-val" id="sys-host-ip">—</span>
        </div>
        <div class="info-item">
          <span class="info-label">Host MAC</span>
          <span class="info-val" id="sys-host-mac">—</span>
        </div>
        <div class="info-item">
          <span class="info-label">Gateway IP</span>
          <span class="info-val" id="sys-gateway-ip">—</span>
        </div>
        <div class="info-item">
          <span class="info-label">Interface</span>
          <span class="info-val interface-desc-scroll" id="sys-interface">—</span>
        </div>
        <div class="info-item">
          <span class="info-label">Sniffer</span>
          <span class="info-val status-live-text" id="sys-sniffer">—</span>
        </div>
        <div class="info-item">
          <span class="info-label">Block Duration</span>
          <span class="info-val" id="sys-block-ttl">—</span>
        </div>
      </div>
    </div>

    <!-- Section 3: Firewall Control -->
    <div class="side-section">
      <div class="side-title side-title-arp"><span class="side-icon">🔒</span>Active Firewall Rules</div>
      <div class="fw-actions">
        <div class="manual-block-form">
          <input type="text" id="manual-block-ip" placeholder="Enter IP address to block...">
          <button id="btn-manual-block" class="tbtn active" style="background:#2a0f0f; border-color:#5a1f1f; color:var(--arp-color); font-weight:bold;">BLOCK</button>
        </div>
        <div class="unblock-all-wrapper">
          <button id="btn-unblock-all" class="tbtn" style="width:100%; text-align:center; padding: 8px;">✕ Clear All Firewall Blocks</button>
        </div>
      </div>
      <ul id="blocked-list">
        <li><span class="bl-none">None currently blocked</span></li>
      </ul>
    </div>

    <!-- Section 4: ARP Baseline Mapping -->
    <div class="side-section">
      <div class="side-title side-title-green"><span class="side-icon">📊</span>ARP Baseline Mapping</div>
      <div class="baseline-search-wrapper">
        <input type="text" id="baseline-search" placeholder="Filter baseline hosts...">
      </div>
      <div class="baseline-table-container">
        <table class="baseline-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>MAC Address</th>
            </tr>
          </thead>
          <tbody id="baseline-tbody">
            <tr><td colspan="2" class="bl-none" style="text-align:center;">Seeding baseline...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Section 5: Attack Command Cheat-Sheet -->
    <div class="side-section" style="border-bottom:none;">
      <div class="side-title side-title-blue collapsible-title" id="cheatsheet-toggle" style="cursor:pointer; display:flex; justify-content:space-between; align-items:center;">
        <span><span class="side-icon">📖</span>Attack Cheat-Sheet</span>
        <span id="cheat-arrow">▼</span>
      </div>
      <div class="cheat-content" id="cheat-container" style="margin-top: 10px;">
        <div class="cheat-entry">
          <div class="cheat-label">1. ARP Spoof Attack (Kali)</div>
          <div class="cheat-desc">Sends forged ARP replies to poison victim tables.</div>
          <div class="cheat-cmd">sudo python3 arp_attack.py</div>
        </div>
        <div class="cheat-entry">
          <div class="cheat-label">2. DDoS Attack (Kali)</div>
          <div class="cheat-desc">Launches TCP SYN, UDP, or multi-vector floods using hping3.</div>
          <div class="cheat-cmd">sudo python3 ddos_attack.py</div>
        </div>
      </div>
    </div>
  </div><!-- /sidebar -->

  <footer>LAN-Shield IDS/IPS  &nbsp;|&nbsp; ARP Spoof Detection (top) &nbsp;·&nbsp; DDoS Victim Alerts (bottom) &nbsp;|&nbsp; Auto-refresh every 3 s</footer>

</div><!-- /layout -->

<script>
// ══════════════════════════════════════════════════════════════
//  Shared state
// ══════════════════════════════════════════════════════════════
let arpEvents  = [];
let ddosAlerts = [];

let arpFilter  = 'ALL';
let arpSearch  = '';
let arpPaused  = false;
let arpCleared = false;
let arpLimit   = 50;

let ddosVictim  = 'ALL';
let ddosSearch  = '';
let ddosPaused  = false;
let ddosCleared = false;

// ── Clock ──────────────────────────────────────────────────────
setInterval(() => {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}, 1000);

// ── HTML escape ────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ══════════════════════════════════════════════════════════════
//  ARP PANEL
// ══════════════════════════════════════════════════════════════

document.querySelectorAll('.filt-arp,.filt-blue,.filt-gray').forEach(btn => {
  if (!btn.dataset.panel) return;
  btn.addEventListener('click', () => {
    document.querySelectorAll('[data-panel="arp"]').forEach(b => {
      b.classList.remove('active');
    });
    btn.classList.add('active');
    arpFilter = btn.dataset.filter;
    renderArp();
  });
});

document.getElementById('arp-search').addEventListener('input', e => {
  arpSearch = e.target.value.toLowerCase();
  renderArp();
});

document.getElementById('pause-arp').addEventListener('click', () => {
  arpPaused = !arpPaused;
  const btn = document.getElementById('pause-arp');
  btn.textContent = arpPaused ? '▶ Resume' : '⏸ Pause';
  btn.classList.toggle('paused', arpPaused);
  document.getElementById('arp-status-badge').textContent = arpPaused ? '⏸ Paused' : '● Monitoring';
  document.getElementById('arp-status-badge').style.color = arpPaused ? 'var(--accent-amber)' : 'var(--accent-green)';
});

document.getElementById('clear-arp').addEventListener('click', () => {
  arpCleared = true;
  document.getElementById('arp-tbody').innerHTML =
    '<tr class="empty-row"><td colspan="4">View cleared — data still collecting in background</td></tr>';
  document.getElementById('arp-row-count').textContent = '';
});

document.getElementById('arp-load-more').addEventListener('click', () => {
  arpLimit = arpLimit === 50 ? 200 : 50;
  document.getElementById('arp-load-more').textContent =
    arpLimit === 200 ? 'Back to 50 events' : 'Load 200 events';
  arpCleared = false;
  fetchArp();
});

function renderArp() {
  if (arpCleared) return;

  let rows = arpFilter === 'ALL'
    ? arpEvents
    : arpEvents.filter(e => e.event_type === arpFilter);

  if (arpSearch) {
    rows = rows.filter(e =>
      (e.src_ip  || '').toLowerCase().includes(arpSearch) ||
      (e.message || '').toLowerCase().includes(arpSearch) ||
      (e.timestamp || '').includes(arpSearch)
    );
  }

  const tbody   = document.getElementById('arp-tbody');
  const wrapper = document.getElementById('arp-wrapper');

  if (rows.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No matching ARP events</td></tr>';
    document.getElementById('arp-row-count').textContent = '';
    return;
  }

  const saved = wrapper.scrollTop;
  tbody.innerHTML = rows.map(e => `
    <tr>
      <td class="td-ts">${esc(e.timestamp)}</td>
      <td><span class="badge-type badge-${esc(e.event_type)}">${esc(e.event_type)}</span></td>
      <td class="td-ip">${esc(e.src_ip || '—')}</td>
      <td class="td-msg">${esc(e.message)}</td>
    </tr>`).join('');
  wrapper.scrollTop = saved;
  document.getElementById('arp-row-count').textContent =
    `${rows.length} row${rows.length !== 1 ? 's' : ''} shown`;
}

async function fetchArp() {
  try {
    const [evRes, blRes] = await Promise.all([
      fetch('/api/events?limit=' + arpLimit),
      fetch('/api/blocked'),
    ]);
    arpEvents = await evRes.json();
    const blocked = await blRes.json();

    document.getElementById('s-arp').textContent    = arpEvents.filter(e=>e.event_type==='ARP_SPOOF').length;
    document.getElementById('s-block').textContent  = arpEvents.filter(e=>e.event_type==='BLOCK').length;
    document.getElementById('s-total').textContent  = arpEvents.length + ddosAlerts.length;
    document.getElementById('s-blocked').textContent = Object.keys(blocked).length;

    const keys = Object.keys(blocked);
    document.getElementById('blocked-list').innerHTML = keys.length
      ? keys.map(ip => `
          <li>
            <div>
              <span class="bl-ip">${esc(ip)}</span>
              <span class="bl-ts">${esc(blocked[ip])}</span>
            </div>
            <button class="tbtn-unblock" onclick="unblockIp('${esc(ip)}')" title="Unblock IP">✕</button>
          </li>`).join('')
      : '<li><span class="bl-none">None currently blocked</span></li>';

    updateSecurityStatus(keys.length);

    if (!arpPaused && !arpCleared) renderArp();
  } catch (err) {
    console.error('ARP fetch failed:', err);
  }
}

// ══════════════════════════════════════════════════════════════
//  DDoS PANEL
// ══════════════════════════════════════════════════════════════

document.getElementById('ddos-search').addEventListener('input', e => {
  ddosSearch = e.target.value.toLowerCase();
  renderDdos();
});

document.getElementById('pause-ddos').addEventListener('click', () => {
  ddosPaused = !ddosPaused;
  const btn = document.getElementById('pause-ddos');
  btn.textContent = ddosPaused ? '▶ Resume' : '⏸ Pause';
  btn.classList.toggle('paused', ddosPaused);
  document.getElementById('ddos-status-badge').textContent = ddosPaused ? '⏸ Paused' : '● Listening';
  document.getElementById('ddos-status-badge').style.color = ddosPaused ? 'var(--accent-amber)' : 'var(--accent-amber)';
});

document.getElementById('clear-ddos').addEventListener('click', () => {
  ddosCleared = true;
  document.getElementById('ddos-tbody').innerHTML =
    '<tr class="empty-row"><td colspan="5">View cleared — data still collecting in background</td></tr>';
  document.getElementById('ddos-row-count').textContent = '';
});

document.getElementById('victim-pills').addEventListener('click', e => {
  const pill = e.target.closest('.vpill');
  if (!pill) return;
  document.querySelectorAll('.vpill').forEach(p => p.classList.remove('active'));
  pill.classList.add('active');
  ddosVictim = pill.dataset.victim;
  renderDdos();
});

function updateVictimPills(alerts) {
  const victims = [...new Set(alerts.map(a => a.victim_ip))].sort();
  const container = document.getElementById('victim-pills');
  const existing = new Set([...container.querySelectorAll('.vpill')].map(p => p.dataset.victim));
  existing.delete('ALL');
  victims.forEach(v => {
    if (!existing.has(v)) {
      const pill = document.createElement('span');
      pill.className = 'vpill';
      pill.dataset.victim = v;
      pill.textContent = v;
      container.appendChild(pill);
    }
  });
}

function renderDdos() {
  if (ddosCleared) return;

  let rows = ddosVictim === 'ALL'
    ? ddosAlerts
    : ddosAlerts.filter(a => a.victim_ip === ddosVictim);

  if (ddosSearch) {
    rows = rows.filter(a =>
      (a.victim_ip   || '').toLowerCase().includes(ddosSearch) ||
      (a.attacker_ip || '').toLowerCase().includes(ddosSearch) ||
      (a.attack_type || '').toLowerCase().includes(ddosSearch) ||
      (a.timestamp   || '').includes(ddosSearch)
    );
  }

  const tbody   = document.getElementById('ddos-tbody');
  const wrapper = document.getElementById('ddos-wrapper');

  if (rows.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="5">No DDoS alerts received yet…</td></tr>';
    document.getElementById('ddos-row-count').textContent = '';
    return;
  }

  const saved = wrapper.scrollTop;
  tbody.innerHTML = rows.map(a => `
    <tr>
      <td class="td-ts">${esc(a.timestamp)}</td>
      <td class="td-victim">${esc(a.victim_ip)}</td>
      <td class="td-attacker">${esc(a.attacker_ip)}</td>
      <td><span class="badge-type badge-ddos">${esc(a.attack_type)}</span></td>
      <td class="td-pkt">${esc(a.packet_count)}</td>
    </tr>`).join('');
  wrapper.scrollTop = saved;

  document.getElementById('ddos-row-count').textContent =
    `${rows.length} alert${rows.length !== 1 ? 's' : ''} shown`;
}

async function fetchDdos() {
  try {
    const res  = await fetch('/api/ddos_alerts');
    ddosAlerts = await res.json();

    const victims = new Set(ddosAlerts.map(a => a.victim_ip));
    document.getElementById('s-ddos').textContent    = ddosAlerts.length;
    document.getElementById('s-victims').textContent = victims.size;
    document.getElementById('s-total').textContent   = arpEvents.length + ddosAlerts.length;

    updateVictimPills(ddosAlerts);
    if (!ddosPaused && !ddosCleared) renderDdos();
  } catch (err) {
    console.error('DDoS fetch failed:', err);
  }
}

// ══════════════════════════════════════════════════════════════
//  Sidebar custom widgets & interactions
// ══════════════════════════════════════════════════════════════

let baselineData = {};
let baselineSearch = '';

document.getElementById('baseline-search').addEventListener('input', e => {
  baselineSearch = e.target.value.toLowerCase();
  renderBaseline();
});

function renderBaseline() {
  const tbody = document.getElementById('baseline-tbody');
  const ips = Object.keys(baselineData);
  
  let filteredIps = ips;
  if (baselineSearch) {
    filteredIps = ips.filter(ip => 
      ip.includes(baselineSearch) || 
      (baselineData[ip] || '').toLowerCase().includes(baselineSearch)
    );
  }
  
  if (filteredIps.length === 0) {
    tbody.innerHTML = '<tr><td colspan="2" class="bl-none" style="text-align:center;">No matching hosts</td></tr>';
    return;
  }
  
  tbody.innerHTML = filteredIps.map(ip => `
    <tr style="cursor:pointer;" onclick="populateManualBlock('${esc(ip)}')" title="Click to fill block input">
      <td style="color:var(--accent-blue);">${esc(ip)}</td>
      <td style="color:var(--text-secondary); font-size:.68rem;">${esc(baselineData[ip])}</td>
    </tr>
  `).join('');
}

function populateManualBlock(ip) {
  document.getElementById('manual-block-ip').value = ip;
}

async function fetchBaseline() {
  try {
    const res = await fetch('/api/baseline');
    baselineData = await res.json();
    renderBaseline();
  } catch (err) {
    console.error('Failed to fetch baseline:', err);
  }
}

async function fetchSystemInfo() {
  try {
    const res = await fetch('/api/system_info');
    const data = await res.json();
    
    document.getElementById('sys-host-ip').textContent = data.host_ip;
    document.getElementById('sys-host-mac').textContent = data.host_mac;
    document.getElementById('sys-gateway-ip').textContent = data.gateway_ip;
    document.getElementById('sys-interface').textContent = data.iface_desc;
    document.getElementById('sys-interface').title = data.iface_desc;
    document.getElementById('sys-sniffer').textContent = data.sniffer_status;
    document.getElementById('sys-block-ttl').textContent = data.block_ttl + 's';
    
    const snifferElement = document.getElementById('sys-sniffer');
    if (data.sniffer_status === 'LIVE') {
      snifferElement.className = 'info-val status-live-text';
      snifferElement.style.color = '';
    } else {
      snifferElement.className = 'info-val';
      snifferElement.style.color = 'var(--accent-red)';
    }
  } catch (err) {
    console.error('Failed to fetch system info:', err);
  }
}

async function unblockIp(ip) {
  try {
    const res = await fetch('/api/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.status === 'success') {
      fetchAll();
    } else {
      alert('Error unblocking IP: ' + data.message);
    }
  } catch (err) {
    console.error('Unblock request failed:', err);
  }
}

document.getElementById('btn-manual-block').addEventListener('click', async () => {
  const ipInput = document.getElementById('manual-block-ip');
  const ip = ipInput.value.trim();
  if (!ip) return;
  
  try {
    const res = await fetch('/api/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.status === 'success') {
      ipInput.value = '';
      fetchAll();
    } else {
      alert('Error blocking IP: ' + data.message);
    }
  } catch (err) {
    console.error('Manual block failed:', err);
  }
});

document.getElementById('btn-unblock-all').addEventListener('click', async () => {
  if (!confirm('Are you sure you want to unblock all IPs?')) return;
  try {
    const res = await fetch('/api/unblock_all', { method: 'POST' });
    const data = await res.json();
    if (data.status === 'success') {
      fetchAll();
    } else {
      alert('Error clearing firewall blocks: ' + data.message);
    }
  } catch (err) {
    console.error('Clear blocks failed:', err);
  }
});

document.getElementById('cheatsheet-toggle').addEventListener('click', () => {
  const container = document.getElementById('cheat-container');
  const arrow = document.getElementById('cheat-arrow');
  const collapsed = container.classList.toggle('collapsed');
  arrow.textContent = collapsed ? '▲' : '▼';
});

// Set default collapsed state for cheat sheet
document.getElementById('cheat-container').classList.add('collapsed');
document.getElementById('cheat-arrow').textContent = '▲';

function updateSecurityStatus(blockedCount) {
  const card = document.getElementById('security-card');
  const title = document.getElementById('security-status-title');
  const desc = document.getElementById('security-status-desc');
  
  const now = new Date();
  let activeAttack = false;
  let activeAttackType = "";
  
  function parseDate(str) {
    if (!str) return new Date(0);
    const parts = str.split(' ');
    if (parts.length < 2) return new Date(0);
    const d = parts[0].split('-');
    const t = parts[1].split(':');
    return new Date(d[0], d[1] - 1, d[2], t[0], t[1], t[2]);
  }
  
  for (let e of arpEvents) {
    if (e.event_type === 'ARP_SPOOF') {
      const diff = (now - parseDate(e.timestamp)) / 1000;
      if (diff >= 0 && diff < 20) {
        activeAttack = true;
        activeAttackType = "ARP Spoofing";
        break;
      }
    }
  }
  
  if (!activeAttack) {
    for (let a of ddosAlerts) {
      const diff = (now - parseDate(a.timestamp)) / 1000;
      if (diff >= 0 && diff < 20) {
        activeAttack = true;
        activeAttackType = "DDoS " + a.attack_type;
        break;
      }
    }
  }
  
  card.classList.remove('status-warning', 'status-critical');
  
  if (activeAttack) {
    card.classList.add('status-critical');
    title.textContent = "ATTACK DETECTED";
    desc.textContent = `Active ${activeAttackType} attempt detected!`;
  } else if (blockedCount > 0) {
    card.classList.add('status-warning');
    title.textContent = "WARNING";
    desc.textContent = `${blockedCount} malicious IP(s) currently blocked.`;
  } else {
    title.textContent = "SECURE";
    desc.textContent = "All systems operating normally.";
  }
}

// ══════════════════════════════════════════════════════════════
//  Unified refresh
// ══════════════════════════════════════════════════════════════
async function fetchAll() {
  await Promise.all([fetchArp(), fetchDdos(), fetchBaseline(), fetchSystemInfo()]);
}

fetchAll();
setInterval(() => { fetchAll(); }, 3000);
</script>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────
#  Flask routes
# ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(_HTML)


@app.route("/api/events")
def api_events():
    """ARP / system events from the local sniff (via logger)."""
    try:
        limit = min(int(flask_request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        limit = 50
    return jsonify(get_recent_events(limit))


@app.route("/api/blocked")
def api_blocked():
    from firewall import _blocked, _blocked_lock
    with _blocked_lock:
        return jsonify(dict(_blocked))


@app.route("/api/ddos_alerts")
def api_ddos_alerts():
    """Return all DDoS alerts received from victim machines (newest first)."""
    with _ddos_lock:
        return jsonify(list(_ddos_alerts))


@app.route("/api/system_info")
def api_system_info():
    import main
    return jsonify({
        "host_ip": getattr(main, "_host_ip", "0.0.0.0"),
        "host_mac": getattr(main, "_host_mac", "00:00:00:00:00:00"),
        "gateway_ip": getattr(main, "_gateway_ip", "0.0.0.0"),
        "iface_desc": getattr(main, "_iface_desc", "Unknown"),
        "block_ttl": Config.BLOCK_DURATION,
        "sniffer_status": "LIVE" if (getattr(main, "_arp_det_ref", None) is not None) else "INACTIVE"
    })


@app.route("/api/baseline")
def api_baseline():
    import main
    arp_det = getattr(main, "_arp_det_ref", None)
    if arp_det is not None:
        with arp_det._lock:
            return jsonify(dict(arp_det._verified_baseline))
    return jsonify({})


@app.route("/api/block", methods=["POST"])
def api_block():
    import main
    fw = getattr(main, "_firewall_ref", None)
    data = flask_request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "IP is required"}), 400
    if fw is not None:
        fw.block(ip, reason="Manual block via Dashboard")
        return jsonify({"status": "success", "message": f"IP {ip} blocked successfully"})
    return jsonify({"status": "error", "message": "Firewall manager not initialized"}), 500


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    import main
    fw = getattr(main, "_firewall_ref", None)
    data = flask_request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "IP is required"}), 400
    if fw is not None:
        fw.unblock(ip)
        return jsonify({"status": "success", "message": f"IP {ip} unblocked successfully"})
    return jsonify({"status": "error", "message": "Firewall manager not initialized"}), 500


@app.route("/api/unblock_all", methods=["POST"])
def api_unblock_all():
    import main
    fw = getattr(main, "_firewall_ref", None)
    if fw is not None:
        fw.unblock_all()
        return jsonify({"status": "success", "message": "All IPs unblocked successfully"})
    return jsonify({"status": "error", "message": "Firewall manager not initialized"}), 500


def start_dashboard():
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(
        host         = "0.0.0.0",
        port         = Config.DASHBOARD_PORT,
        debug        = False,
        use_reloader = False,
    )


if __name__ == "__main__":
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(
        host         = "0.0.0.0",
        port         = 5001,
        debug        = False,
        use_reloader = False,
    )
