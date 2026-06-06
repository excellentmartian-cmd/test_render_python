#!/usr/bin/env python3
"""
VPNGate 节点查看器 - 精简版
功能：查看节点列表、速度/延迟/评分、下载 .ovpn 配置文件
无 OpenVPN、无代理转发、无 tun 网卡
"""
from __future__ import annotations

import base64
import csv
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.parse
import urllib.request
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# ── 配置（优先读环境变量）──────────────────────────────────────────
API_URL            = "https://www.vpngate.net/api/iphone/"
UI_HOST            = os.environ.get("UI_HOST", "0.0.0.0")
UI_PORT            = int(os.environ.get("UI_PORT", "8787"))
FETCH_INTERVAL     = int(os.environ.get("FETCH_INTERVAL_SECONDS", "1200"))  # 20分钟刷新一次
MAX_NODES          = int(os.environ.get("MAX_NODES", "300"))

# 用户名密码：优先读环境变量，否则随机生成
WEB_USERNAME = os.environ.get("WEB_USERNAME", "")
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")

ROOT_DIR  = Path(__file__).resolve().parent
DATA_DIR  = Path(os.environ.get("DATA_DIR", str(ROOT_DIR / "data")))
NODES_FILE = DATA_DIR / "nodes.json"
AUTH_FILE  = DATA_DIR / "auth.json"

lock = threading.RLock()
active_sessions: dict[str, float] = {}   # token → 过期时间
login_attempts:  dict[str, list] = {}    # IP → [时间戳, ...]  速率限制
last_fetch_time  = 0.0
last_fetch_status = "未开始"

# ── Session 清理（每小时清一次过期session，防内存泄漏）──────────────
def session_cleanup_loop() -> None:
    while True:
        time.sleep(3600)
        now = time.time()
        with lock:
            expired = [t for t, exp in active_sessions.items() if exp < now]
            for t in expired:
                del active_sessions[t]
        if expired:
            print(f"[Session] 清理 {len(expired)} 个过期会话", flush=True)

# ── 登录速率限制 ──────────────────────────────────────────────────
MAX_ATTEMPTS   = 10   # 10分钟内最多10次
RATE_WINDOW    = 600  # 秒

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    with lock:
        attempts = [t for t in login_attempts.get(ip, [])
                    if now - t < RATE_WINDOW]
        login_attempts[ip] = attempts
        return len(attempts) >= MAX_ATTEMPTS

def record_attempt(ip: str) -> None:
    now = time.time()
    with lock:
        login_attempts.setdefault(ip, []).append(now)

# ── 国家翻译表 ────────────────────────────────────────────────────
COUNTRY_TRANSLATIONS = {
    "Japan": "日本", "Korea Republic of": "韩国", "Korea": "韩国",
    "Republic of Korea": "韩国", "Thailand": "泰国", "United States": "美国",
    "United Kingdom": "英国", "Russian Federation": "俄罗斯", "Russian": "俄罗斯",
    "Viet Nam": "越南", "Vietnam": "越南", "China": "中国", "Taiwan": "台湾",
    "Taiwan Province of China": "台湾", "Hong Kong": "香港", "Singapore": "新加坡",
    "Malaysia": "马来西亚", "Indonesia": "印度尼西亚", "India": "印度",
    "Philippines": "菲律宾", "Australia": "澳大利亚", "New Zealand": "新西兰",
    "Canada": "加拿大", "Ukraine": "乌克兰", "France": "法国", "Germany": "德国",
    "Netherlands": "荷兰", "Sweden": "瑞典", "Norway": "挪威", "Spain": "西班牙",
    "Turkey": "土耳其", "South Africa": "南非", "Brazil": "巴西",
    "Argentina": "阿根廷", "Chile": "智利", "Mexico": "墨西哥", "Egypt": "埃及",
    "Romania": "罗马尼亚", "Poland": "波兰", "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚", "Mongolia": "蒙古", "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗", "Iraq": "伊拉克", "Colombia": "哥伦比亚", "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰", "Italy": "意大利", "Switzerland": "瑞士",
    "Belgium": "比利时", "Austria": "奥地利", "Denmark": "丹麦",
    "Finland": "芬兰", "Portugal": "葡萄牙", "Greece": "希腊",
    "Czech Republic": "捷克", "Hungary": "匈牙利", "Israel": "以色列",
    "United Arab Emirates": "阿联酋", "UAE": "阿联酋", "Macao": "澳门",
    "Macau": "澳门", "Iceland": "冰岛", "Luxembourg": "卢森堡",
}

# ── 工具函数 ──────────────────────────────────────────────────────
def parse_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0

def safe_name(v: str) -> str:
    v = re.sub(r"[^A-Za-z0-9_.-]+", "_", v.strip())
    return v.strip("._") or "node"

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

# ── 认证管理 ──────────────────────────────────────────────────────
def load_auth() -> dict[str, str]:
    global WEB_USERNAME, WEB_PASSWORD
    auth = read_json(AUTH_FILE, {})
    # 环境变量优先
    username = WEB_USERNAME or auth.get("username", "")
    password = WEB_PASSWORD or auth.get("password", "")
    secret   = auth.get("secret_path", "")

    updated = False
    if not username:
        username = "admin"
        updated = True
    if not password:
        password = secrets.token_urlsafe(12)
        updated = True
        print(f"[认证] 随机生成密码: {password}", flush=True)
    # secret_path 禁用，Render 等云平台用根路径访问
    secret = ""

    if updated and not (WEB_USERNAME and WEB_PASSWORD):
        write_json(AUTH_FILE, {
            "username": username,
            "password": password,
            "secret_path": secret
        })

    return {"username": username, "password": password, "secret_path": secret}

def get_secret_path() -> str:
    return load_auth().get("secret_path", "")

# ── VPNGate 抓取与解析 ────────────────────────────────────────────
def parse_remote(config_text: str, fallback_ip: str = "") -> tuple[str, int, str]:
    remote_host, remote_port, proto = fallback_ip, 0, "unknown"
    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        if parts[0].lower() == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
        elif parts[0].lower() == "remote" and len(parts) >= 3:
            remote_host = parts[1]
            remote_port = int(parts[2]) if parts[2].isdigit() else 0
            if len(parts) >= 4:
                proto = parts[3].lower()
    return remote_host, remote_port, proto

def fetch_nodes() -> list[dict[str, Any]]:
    global last_fetch_time, last_fetch_status
    try:
        print(f"[抓取] 正在从 VPNGate 获取节点列表...", flush=True)
        req = urllib.request.Request(
            API_URL,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            text = r.read().decode("utf-8", errors="replace")

        lines = [l for l in text.splitlines() if l and not l.startswith("*")]
        if lines and lines[0].startswith("#"):
            lines[0] = lines[0][1:]

        rows = list(csv.DictReader(lines))
        nodes = []
        for row in rows[:MAX_NODES]:
            encoded = row.get("OpenVPN_ConfigData_Base64", "")
            if not encoded:
                continue
            try:
                config_text = base64.b64decode(
                    encoded.encode("ascii"), validate=False
                ).decode("utf-8", errors="replace")
            except Exception:
                continue

            ip           = row.get("IP", "")
            country_long = row.get("CountryLong", "")
            country_short= row.get("CountryShort", "")
            remote_host, remote_port, proto = parse_remote(config_text, ip)
            node_id = safe_name("_".join([
                country_short or "XX", ip or remote_host,
                str(remote_port), proto
            ]))
            country_zh = COUNTRY_TRANSLATIONS.get(
                country_long,
                COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long)
            )
            nodes.append({
                "id":           node_id,
                "country":      country_zh,
                "country_short":country_short,
                "host_name":    row.get("HostName", ""),
                "ip":           ip,
                "score":        parse_int(row.get("Score")),
                "ping":         parse_int(row.get("Ping")),
                "speed":        parse_int(row.get("Speed")),
                "sessions":     parse_int(row.get("NumVpnSessions")),
                "proto":        proto,
                "remote_host":  remote_host,
                "remote_port":  remote_port,
                "config_text":  config_text,
                "fetched_at":   time.time(),
            })

        nodes.sort(key=lambda n: (-n["score"], n["ping"]))
        write_json(NODES_FILE, nodes)
        last_fetch_time   = time.time()
        last_fetch_status = f"成功，共 {len(nodes)} 个节点"
        print(f"[抓取] 完成，获取到 {len(nodes)} 个节点", flush=True)
        return nodes
    except Exception as e:
        last_fetch_status = f"失败: {e}"
        print(f"[抓取] 失败: {e}", flush=True)
        return []

def collector_loop() -> None:
    while True:
        fetch_nodes()
        time.sleep(FETCH_INTERVAL)

# ── HTTP 处理器 ───────────────────────────────────────────────────
LOGIN_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>VPNGate 节点查看器</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
    :root {
      --bg-dark:#0b0f19; --bg-surface:rgba(22,30,49,0.6);
      --border-color:rgba(255,255,255,0.08); --text-primary:#f3f4f6;
      --text-secondary:#9ca3af; --primary:#6366f1;
      --primary-gradient:linear-gradient(135deg,#6366f1 0%,#4f46e5 100%);
      --primary-hover:linear-gradient(135deg,#4f46e5 0%,#3730a3 100%);
    }
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Outfit',sans-serif;background-color:var(--bg-dark);
      background-image:radial-gradient(at 0% 0%,rgba(99,102,241,0.15) 0px,transparent 50%),
        radial-gradient(at 100% 0%,rgba(16,185,129,0.08) 0px,transparent 50%);
      color:var(--text-primary);min-height:100vh;display:flex;
      align-items:center;justify-content:center}
    .login-card{background:var(--bg-surface);border:1px solid var(--border-color);
      border-radius:16px;padding:40px;width:380px;max-width:90vw;
      backdrop-filter:blur(20px)}
    .brand-logo{width:52px;height:52px;background:var(--primary-gradient);
      border-radius:14px;display:flex;align-items:center;justify-content:center;
      margin:0 auto 20px;color:#fff}
    h2{text-align:center;font-size:22px;font-weight:600;margin-bottom:6px}
    .subtitle{text-align:center;color:var(--text-secondary);font-size:13px;margin-bottom:28px}
    label{display:block;font-size:13px;color:var(--text-secondary);margin-bottom:6px}
    input{width:100%;background:rgba(255,255,255,0.05);border:1px solid var(--border-color);
      border-radius:8px;padding:10px 14px;color:var(--text-primary);font-size:14px;
      outline:none;transition:border-color .2s}
    input:focus{border-color:#6366f1}
    .form-group{margin-bottom:16px}
    .error{color:#f43f5e;font-size:12px;margin-top:8px;display:none}
    .btn{width:100%;padding:12px;background:var(--primary-gradient);border:none;
      border-radius:10px;color:#fff;font-size:15px;font-weight:600;
      cursor:pointer;margin-top:8px;transition:all .2s}
    .btn:hover{background:var(--primary-hover)}
    .btn:disabled{opacity:.6;cursor:not-allowed}
  </style>
</head>
<body>
<div class="login-card">
  <div class="brand-logo">
    <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
      <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
    </svg>
  </div>
  <h2>VPNGate 节点查看器</h2>
  <p class="subtitle">请输入管理账号和密码</p>
  <div class="form-group">
    <label>账号</label>
    <input type="text" id="uname" placeholder="用户名" autocomplete="username"/>
  </div>
  <div class="form-group">
    <label>密码</label>
    <input type="password" id="pwd" placeholder="密码" autocomplete="current-password"/>
    <div class="error" id="err"></div>
  </div>
  <button class="btn" id="btn" onclick="doLogin()">登录</button>
</div>
<script>
document.addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });
async function doLogin(){
  const uname=document.getElementById('uname').value.trim();
  const pwd=document.getElementById('pwd').value.trim();
  const err=document.getElementById('err');
  const btn=document.getElementById('btn');
  err.style.display='none'; btn.disabled=true; btn.textContent='验证中...';
  try{
    const r=await fetch('./api/login',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:uname,password:pwd})});
    const d=await r.json();
    if(r.ok && d.ok){ window.location.reload(); }
    else{ err.textContent=d.error||'账号或密码不正确'; err.style.display='block'; }
  }catch(e){ err.textContent='连接失败，请重试'; err.style.display='block'; }
  btn.disabled=false; btn.textContent='登录';
}
</script>
</body>
</html>"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>VPNGate 节点查看器</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    :root{
      --bg-dark:#0b0f19; --bg-surface:rgba(22,30,49,0.6);
      --bg-surface-hover:rgba(30,41,67,0.85);
      --border-color:rgba(255,255,255,0.08);
      --border-color-hover:rgba(99,102,241,0.35);
      --text-primary:#f3f4f6; --text-secondary:#9ca3af;
      --primary:#6366f1;
      --primary-gradient:linear-gradient(135deg,#6366f1 0%,#4f46e5 100%);
      --success:#10b981; --danger:#f43f5e; --warning:#f59e0b;
    }
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Outfit',sans-serif;background-color:var(--bg-dark);
      background-image:radial-gradient(at 0% 0%,rgba(99,102,241,0.15) 0px,transparent 50%),
        radial-gradient(at 100% 0%,rgba(16,185,129,0.08) 0px,transparent 50%);
      background-attachment:fixed;color:var(--text-primary);min-height:100vh;
      -webkit-font-smoothing:antialiased}
    header{padding:14px 28px;background:rgba(11,15,25,0.8);backdrop-filter:blur(20px);
      border-bottom:1px solid var(--border-color);display:flex;align-items:center;
      justify-content:space-between;position:sticky;top:0;z-index:100}
    .brand{display:flex;align-items:center;gap:10px;font-size:16px;font-weight:600}
    .brand-icon{width:34px;height:34px;background:linear-gradient(135deg,#6366f1,#4f46e5);
      border-radius:8px;display:flex;align-items:center;justify-content:center}
    .header-actions{display:flex;align-items:center;gap:10px}
    .btn{padding:7px 16px;border-radius:8px;border:none;font-size:13px;font-weight:500;
      cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:6px}
    .btn-primary{background:var(--primary-gradient);color:#fff}
    .btn-primary:hover{opacity:.9;transform:translateY(-1px)}
    .btn-ghost{background:rgba(255,255,255,0.05);color:var(--text-secondary);
      border:1px solid var(--border-color)}
    .btn-ghost:hover{background:rgba(255,255,255,0.1);color:var(--text-primary)}
    .btn-success{background:linear-gradient(135deg,#34d399,#059669);color:#fff}
    .btn-success:hover{opacity:.9}
    main{padding:24px 28px;max-width:1400px;margin:0 auto}
    .stats-bar{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
      gap:14px;margin-bottom:24px}
    .stat-card{background:var(--bg-surface);border:1px solid var(--border-color);
      border-radius:12px;padding:16px 20px;backdrop-filter:blur(10px)}
    .stat-label{font-size:12px;color:var(--text-secondary);margin-bottom:4px}
    .stat-value{font-size:22px;font-weight:600}
    .filter-bar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;align-items:center}
    .filter-bar input,.filter-bar select{
      background:rgba(255,255,255,0.05);border:1px solid var(--border-color);
      border-radius:8px;padding:8px 12px;color:var(--text-primary);font-size:13px;
      outline:none;transition:border-color .2s}
    .filter-bar input:focus,.filter-bar select:focus{border-color:#6366f1}
    .filter-bar input{flex:1;min-width:160px}
    .filter-bar select option{background:#1a2235}
    table{width:100%;border-collapse:collapse}
    .table-wrap{background:var(--bg-surface);border:1px solid var(--border-color);
      border-radius:14px;overflow:hidden;backdrop-filter:blur(10px)}
    th{padding:11px 14px;font-size:12px;color:var(--text-secondary);font-weight:500;
      text-align:left;border-bottom:1px solid var(--border-color);
      background:rgba(255,255,255,0.02);white-space:nowrap;cursor:pointer;
      user-select:none}
    th:hover{color:var(--text-primary)}
    th .sort-icon{opacity:.4;margin-left:4px}
    th.sort-asc .sort-icon::after{content:'↑'}
    th.sort-desc .sort-icon::after{content:'↓'}
    th:not(.sort-asc):not(.sort-desc) .sort-icon::after{content:'↕'}
    td{padding:10px 14px;font-size:13px;border-bottom:1px solid var(--border-color);
      vertical-align:middle}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:var(--bg-surface-hover)}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:500}
    .badge-tcp{background:rgba(99,102,241,0.15);color:#818cf8}
    .badge-udp{background:rgba(16,185,129,0.15);color:#34d399}
    .speed-bar{height:4px;border-radius:2px;background:rgba(255,255,255,0.08);
      width:80px;overflow:hidden;display:inline-block;vertical-align:middle;margin-left:6px}
    .speed-fill{height:100%;border-radius:2px;
      background:linear-gradient(90deg,#6366f1,#10b981);transition:width .3s}
    .mono{font-family:'JetBrains Mono',monospace;font-size:12px}
    .flag{font-size:18px;margin-right:6px}
    .ping-good{color:#10b981} .ping-ok{color:#f59e0b} .ping-bad{color:#f43f5e}
    .loading{text-align:center;padding:60px;color:var(--text-secondary)}
    .spinner{width:36px;height:36px;border:3px solid rgba(255,255,255,0.1);
      border-top-color:#6366f1;border-radius:50%;animation:spin 0.8s linear infinite;
      margin:0 auto 14px}
    @keyframes spin{to{transform:rotate(360deg)}}
    .empty{text-align:center;padding:60px;color:var(--text-secondary)}
    .status-dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:6px}
    .dot-ok{background:#10b981} .dot-warn{background:#f59e0b}
    .toast{position:fixed;bottom:24px;right:24px;background:#1e2940;
      border:1px solid var(--border-color);border-radius:10px;padding:12px 18px;
      font-size:13px;z-index:999;transition:opacity .3s;pointer-events:none}
    @media(max-width:700px){
      main{padding:16px} header{padding:12px 16px}
      .stats-bar{grid-template-columns:repeat(2,1fr)}
      td,th{padding:8px 10px}
      .speed-bar{display:none}
    }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <div class="brand-icon">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="white" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/>
      </svg>
    </div>
    VPNGate 节点查看器
  </div>
  <div class="header-actions">
    <span id="fetch_status" style="font-size:12px;color:var(--text-secondary)"></span>
    <button class="btn btn-ghost" onclick="refreshNodes()">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
      </svg>
      刷新节点
    </button>
    <button class="btn btn-ghost" onclick="logout()">退出</button>
  </div>
</header>

<main>
  <div class="stats-bar">
    <div class="stat-card">
      <div class="stat-label">节点总数</div>
      <div class="stat-value" id="stat_total">—</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">涵盖国家/地区</div>
      <div class="stat-value" id="stat_countries">—</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">平均延迟</div>
      <div class="stat-value" id="stat_avgping">—</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">最后更新</div>
      <div class="stat-value" style="font-size:14px" id="stat_updated">—</div>
    </div>
  </div>

  <div class="filter-bar">
    <input type="text" id="search" placeholder="搜索国家、IP、协议..." oninput="applyFilter()"/>
    <select id="filter_proto" onchange="applyFilter()">
      <option value="">全部协议</option>
      <option value="tcp">TCP</option>
      <option value="udp">UDP</option>
    </select>
    <select id="filter_country" onchange="applyFilter()">
      <option value="">全部国家</option>
    </select>
    <select id="sort_by" onchange="applyFilter()">
      <option value="score">按评分排序</option>
      <option value="ping">按延迟排序</option>
      <option value="speed">按速度排序</option>
      <option value="sessions">按在线人数排序</option>
    </select>
  </div>

  <div class="table-wrap">
    <div id="loading" class="loading">
      <div class="spinner"></div>
      正在加载节点列表...
    </div>
    <div id="empty" class="empty" style="display:none">没有找到符合条件的节点</div>
    <table id="table" style="display:none">
      <thead>
        <tr>
          <th>国家/地区</th>
          <th>IP 地址</th>
          <th>协议</th>
          <th>端口</th>
          <th>评分</th>
          <th>延迟 (ms)</th>
          <th>速度 (Mbps)</th>
          <th>在线人数</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
</main>

<div class="toast" id="toast" style="opacity:0"></div>

<script>
let allNodes = [];
let filteredNodes = [];

const COUNTRY_FLAGS = {
  'JP':'🇯🇵','KR':'🇰🇷','TH':'🇹🇭','US':'🇺🇸','GB':'🇬🇧','RU':'🇷🇺',
  'VN':'🇻🇳','CN':'🇨🇳','TW':'🇹🇼','HK':'🇭🇰','SG':'🇸🇬','MY':'🇲🇾',
  'ID':'🇮🇩','IN':'🇮🇳','PH':'🇵🇭','AU':'🇦🇺','NZ':'🇳🇿','CA':'🇨🇦',
  'UA':'🇺🇦','FR':'🇫🇷','DE':'🇩🇪','NL':'🇳🇱','SE':'🇸🇪','NO':'🇳🇴',
  'ES':'🇪🇸','TR':'🇹🇷','ZA':'🇿🇦','BR':'🇧🇷','AR':'🇦🇷','CL':'🇨🇱',
  'MX':'🇲🇽','EG':'🇪🇬','RO':'🇷🇴','PL':'🇵🇱','KZ':'🇰🇿','GE':'🇬🇪',
  'MN':'🇲🇳','SA':'🇸🇦','IR':'🇮🇷','IQ':'🇮🇶','CO':'🇨🇴','KH':'🇰🇭',
  'IE':'🇮🇪','IT':'🇮🇹','CH':'🇨🇭','BE':'🇧🇪','AT':'🇦🇹','DK':'🇩🇰',
  'FI':'🇫🇮','PT':'🇵🇹','GR':'🇬🇷','CZ':'🇨🇿','HU':'🇭🇺','IL':'🇮🇱',
  'AE':'🇦🇪','MO':'🇲🇴','IS':'🇮🇸','LU':'🇱🇺',
};

function fmtSpeed(bps){
  if(!bps) return '—';
  const mbps = bps/1e6;
  return mbps >= 100 ? Math.round(mbps)+'M' : mbps.toFixed(1)+'M';
}

function fmtSpeedNum(bps){ return bps ? bps/1e6 : 0; }

function maxSpeed(nodes){ return Math.max(...nodes.map(n=>n.speed||0), 1); }

function pingClass(ms){
  if(!ms) return '';
  if(ms<100) return 'ping-good';
  if(ms<300) return 'ping-ok';
  return 'ping-bad';
}

function showToast(msg, duration=2500){
  const t=document.getElementById('toast');
  t.textContent=msg; t.style.opacity='1';
  setTimeout(()=>{ t.style.opacity='0'; }, duration);
}

async function load(){
  try{
    const r = await fetch('./api/nodes');
    const d = await r.json();
    allNodes = d.nodes || [];

    // 更新统计
    document.getElementById('stat_total').textContent = allNodes.length;
    const countries = new Set(allNodes.map(n=>n.country).filter(Boolean));
    document.getElementById('stat_countries').textContent = countries.size;
    const pings = allNodes.map(n=>n.ping).filter(Boolean);
    const avgPing = pings.length ? Math.round(pings.reduce((a,b)=>a+b,0)/pings.length) : 0;
    document.getElementById('stat_avgping').textContent = avgPing ? avgPing+'ms' : '—';
    const upd = d.last_fetch ? new Date(d.last_fetch*1000).toLocaleTimeString('zh-CN') : '—';
    document.getElementById('stat_updated').textContent = upd;
    document.getElementById('fetch_status').textContent = d.fetch_status || '';

    // 填充国家下拉
    const sel = document.getElementById('filter_country');
    const cur = sel.value;
    sel.innerHTML = '<option value="">全部国家</option>';
    [...countries].sort().forEach(c=>{
      const o=document.createElement('option');
      o.value=c; o.textContent=c;
      sel.appendChild(o);
    });
    sel.value = cur;

    applyFilter();
    document.getElementById('loading').style.display='none';
  }catch(e){
    document.getElementById('loading').innerHTML='<div class="empty">加载失败：'+e.message+'</div>';
  }
}

function applyFilter(){
  const q = document.getElementById('search').value.toLowerCase();
  const proto = document.getElementById('filter_proto').value;
  const country = document.getElementById('filter_country').value;
  const sortBy = document.getElementById('sort_by').value;

  filteredNodes = allNodes.filter(n=>{
    if(proto && !(n.proto||'').includes(proto)) return false;
    if(country && n.country !== country) return false;
    if(q){
      const hay = [n.country,n.ip,n.remote_host,n.proto,n.host_name].join(' ').toLowerCase();
      if(!hay.includes(q)) return false;
    }
    return true;
  });

  filteredNodes.sort((a,b)=>{
    if(sortBy==='ping') return (a.ping||9999)-(b.ping||9999);
    if(sortBy==='speed') return (b.speed||0)-(a.speed||0);
    if(sortBy==='sessions') return (b.sessions||0)-(a.sessions||0);
    return (b.score||0)-(a.score||0);
  });

  renderTable();
}

function renderTable(){
  const tbody = document.getElementById('tbody');
  const table = document.getElementById('table');
  const empty = document.getElementById('empty');

  if(!filteredNodes.length){
    table.style.display='none';
    empty.style.display='block';
    return;
  }
  table.style.display='table';
  empty.style.display='none';

  const maxSpd = maxSpeed(filteredNodes);

  tbody.innerHTML = filteredNodes.map(n=>{
    const flag = COUNTRY_FLAGS[n.country_short] || '🌐';
    const pClass = pingClass(n.ping);
    const speedPct = maxSpd ? Math.round((n.speed||0)/maxSpd*100) : 0;
    const proto = (n.proto||'').includes('tcp') ? 
      '<span class="badge badge-tcp">TCP</span>' :
      '<span class="badge badge-udp">UDP</span>';
    return `<tr>
      <td><span class="flag">${flag}</span>${n.country||'—'}</td>
      <td class="mono">${n.ip||n.remote_host||'—'}</td>
      <td>${proto}</td>
      <td class="mono">${n.remote_port||'—'}</td>
      <td>${n.score ? n.score.toLocaleString() : '—'}</td>
      <td class="${pClass}">${n.ping||'—'}</td>
      <td>${fmtSpeed(n.speed)}
        <span class="speed-bar"><span class="speed-fill" style="width:${speedPct}%"></span></span>
      </td>
      <td>${n.sessions||'—'}</td>
      <td>
        <button class="btn btn-success" onclick="downloadOvpn('${n.id}')" style="padding:5px 12px;font-size:12px">
          下载 .ovpn
        </button>
      </td>
    </tr>`;
  }).join('');
}

async function downloadOvpn(nodeId){
  const filename = nodeId + '.ovpn';
  try{
    const r = await fetch('./configs/'+filename);
    if(!r.ok){ showToast('下载失败：节点配置不存在'); return; }
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    showToast('已下载：'+filename);
  }catch(e){ showToast('下载出错：'+e.message); }
}

async function refreshNodes(){
  document.getElementById('fetch_status').textContent='正在刷新...';
  try{
    await fetch('./api/refresh', {method:'POST'});
    showToast('已触发刷新，约20秒后完成');
    setTimeout(load, 22000);
  }catch(e){ showToast('刷新失败：'+e.message); }
}

async function logout(){
  await fetch('./api/logout', {method:'POST'});
  window.location.reload();
}

load();
setInterval(load, 120000); // 每2分钟自动刷新显示
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # 关闭默认访问日志

    def get_secret_path(self) -> str:
        return load_auth().get("secret_path", "")

    def validate_path(self) -> str:
        parsed = urllib.parse.urlparse(self.path)
        path   = urllib.parse.unquote(parsed.path).rstrip("/") or "/"
        secret = self.get_secret_path()
        prefix = f"/{secret}" if secret else ""
        if secret:
            if not path.startswith(prefix):
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()
                return ""
            path = path[len(prefix):] or "/"
        return path

    def is_authorized(self) -> bool:
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        for item in cookie_header.split(";"):
            item = item.strip()
            if "=" in item:
                k, v = item.split("=", 1)
                cookies[k.strip()] = v.strip()
        token = cookies.get("session", "")
        with lock:
            exp = active_sessions.get(token, 0)
        return bool(token and exp > time.time())

    def send_bytes(self, body: bytes, ctype: str,
                   status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any,
                  status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(
            json.dumps(data, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8", status
        )

    def do_GET(self) -> None:
        path = self.validate_path()
        if not path:
            return

        if not self.is_authorized():
            if path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"),
                                "text/html; charset=utf-8")
            else:
                self.send_json({"error": "Unauthorized"},
                               HTTPStatus.UNAUTHORIZED)
            return

        if path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"),
                            "text/html; charset=utf-8")

        elif path == "/api/nodes":
            nodes = read_json(NODES_FILE, [])
            stripped = []
            for n in nodes:
                s = {k: v for k, v in n.items() if k != "config_text"}
                stripped.append(s)
            self.send_json({
                "nodes":        stripped,
                "last_fetch":   last_fetch_time,
                "fetch_status": last_fetch_status,
            })

        elif path.startswith("/configs/"):
            filename = urllib.parse.unquote(path[len("/configs/"):])
            nodes = read_json(NODES_FILE, [])
            node  = next(
                (n for n in nodes
                 if n.get("id") + ".ovpn" == filename),
                None
            )
            if node and node.get("config_text"):
                body = node["config_text"].encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type",
                                 "application/x-openvpn-profile")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_json({"error": "not found"},
                               HTTPStatus.NOT_FOUND)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = self.validate_path()
        if not path:
            return

        if path == "/api/login":
            client_ip = (
                self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or self.client_address[0]
            )
            # 速率限制检查
            if is_rate_limited(client_ip):
                self.send_json(
                    {"ok": False, "error": "登录尝试过于频繁，请10分钟后再试"},
                    HTTPStatus.TOO_MANY_REQUESTS
                )
                return
            length  = parse_int(self.headers.get("Content-Length"))
            payload = json.loads(
                self.rfile.read(length).decode("utf-8") or "{}"
            )
            auth    = load_auth()
            in_user = str(payload.get("username", ""))
            in_pass = str(payload.get("password", ""))
            # 记录本次尝试（无论成功失败）
            record_attempt(client_ip)
            if in_user == auth["username"] and in_pass == auth["password"]:
                token  = uuid.uuid4().hex
                with lock:
                    active_sessions[token] = time.time() + 30 * 24 * 3600
                secret = self.get_secret_path()
                cp     = f"/{secret}/" if secret else "/"
                # 判断是否 HTTPS（Render/Cloudflare等反代场景加Secure标记）
                is_https = (
                    self.headers.get("X-Forwarded-Proto", "") == "https"
                    or self.headers.get("X-Forwarded-Ssl", "") == "on"
                )
                secure_flag = "; Secure" if is_https else ""
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type",
                                 "application/json; charset=utf-8")
                self.send_header(
                    "Set-Cookie",
                    f"session={token}; Path={cp}; HttpOnly; SameSite=Lax"
                    f"; Max-Age=2592000{secure_flag}"
                )
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            else:
                self.send_json(
                    {"ok": False, "error": "用户名或密码不正确"},
                    HTTPStatus.FORBIDDEN
                )
            return

        if path == "/api/logout":
            cookie_header = self.headers.get("Cookie", "")
            cookies = {}
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
            token = cookies.get("session", "")
            with lock:
                active_sessions.pop(token, None)
            secret = self.get_secret_path()
            cp = f"/{secret}/" if secret else "/"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header(
                "Set-Cookie",
                f"session=; Path={cp}; HttpOnly; SameSite=Lax; Max-Age=0"
            )
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if path == "/api/refresh":
            threading.Thread(target=fetch_nodes, daemon=True).start()
            self.send_json({"ok": True, "message": "正在后台刷新节点列表"})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)


# ── 启动 ──────────────────────────────────────────────────────────
def main() -> None:
    ensure_dirs()
    auth = load_auth()
    secret = auth.get("secret_path", "")
    print(f"[启动] VPNGate 节点查看器", flush=True)
    print(f"[启动] 地址: http://{UI_HOST}:{UI_PORT}/{secret}/", flush=True)
    print(f"[启动] 账号: {auth['username']}", flush=True)
    print(f"[启动] 密码: {auth['password']}", flush=True)

    # 启动时立即抓取一次
    threading.Thread(target=collector_loop, daemon=True).start()

    # 启动 Session 清理线程
    threading.Thread(target=session_cleanup_loop, daemon=True).start()

    server = ThreadingHTTPServer((UI_HOST, UI_PORT), Handler)
    print(f"[启动] 服务已启动，等待连接...", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
