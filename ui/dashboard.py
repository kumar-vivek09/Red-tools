"""Flask dashboard preserving the legacy scan route and adding modular workspaces."""

import json

from flask import Flask, jsonify, render_template_string, request

from services.malware.ai_malware_analyst import AIMalwareAnalyst
from services.malware.sample_uploader import SampleUploader
from services.sandbox.controller import SandboxController
from services.malware.static_analyzer import StaticAnalyzer
from services.malware.telemetry_collector import TelemetryCollector
from services.recon.service import ReconService

app = Flask(__name__)

recon_service = ReconService()
sample_uploader = SampleUploader()
static_analyzer = StaticAnalyzer()
sandbox_controller = SandboxController()
telemetry_collector = TelemetryCollector()
malware_analyst = AIMalwareAnalyst()


HOME_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>ARCHAI X Workspace</title>
  <style>
    body { margin: 0; font-family: Arial, sans-serif; background: #090c16; color: #e6eefc; }
    .shell { display: grid; grid-template-columns: 280px 1fr; min-height: 100vh; }
    .sidebar { padding: 24px; border-right: 1px solid #1f2a44; background: linear-gradient(180deg, #0c1220 0%, #0b1020 100%); }
    .brand { font-size: 1.3rem; font-weight: 700; margin-bottom: 8px; }
    .tag { color: #8fd3ff; font-size: 0.9rem; margin-bottom: 24px; }
    .nav-block { margin-top: 24px; }
    .nav-title { text-transform: uppercase; letter-spacing: 0.08em; color: #8aa0d8; font-size: 0.8rem; margin-bottom: 12px; }
    .nav a { display: block; padding: 10px 12px; text-decoration: none; color: #d7e4ff; margin-bottom: 8px; border-radius: 12px; border: 1px solid transparent; }
    .nav a:hover, .nav a.active { border-color: #2f66ff; background: rgba(47, 102, 255, 0.12); }
    .content { padding: 28px; }
    .hero { border: 1px solid #22335c; border-radius: 18px; padding: 24px; background: linear-gradient(135deg, rgba(21, 35, 63, 0.95), rgba(10, 14, 26, 0.96)); }
    .hero h1 { margin-top: 0; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top: 18px; }
    .card { border: 1px solid #1f2a44; border-radius: 16px; padding: 18px; background: rgba(9, 14, 26, 0.88); }
    .card h2 { margin-top: 0; }
    .web { color: #90f2ff; }
    .malware { color: #ff9da8; }
    .status { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 0.8rem; }
    .status.online { background: rgba(44, 198, 126, 0.14); color: #7ef9c0; }
    .status.operational { background: rgba(47, 102, 255, 0.16); color: #93bbff; }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">ARCHAI X</div>
      <div class="tag">AI-orchestrated cyber research workstation</div>
      <div class="status online">Status: Online</div>
      <div class="nav-block">
        <div class="nav-title">Primary workspace</div>
        <nav class="nav">
          <a href="/web" class="active">Web Intel</a>
          <a href="/scan/scanme.nmap.org">Recon Console</a>
          <a href="/malware">Malware Lab</a>
        </nav>
      </div>
    </aside>
    <main class="content">
      <div class="hero">
        <p class="status operational">Operational Mode: Modular</p>
        <h1>Cyber research operating system</h1>
        <p>Preserved recon engines, modular service layer, and a separate malware workspace are now available for safe expansion.</p>
      </div>
      <div class="grid">
        <div class="card">
          <h2 class="web">Web Analysis Workspace</h2>
          <p>Attack surface mapping, live telemetry, endpoint relationships, and recon orchestration remain intact.</p>
        </div>
        <div class="card">
          <h2 class="malware">Malware Analysis Workspace</h2>
          <p>Isolated sample ingestion, static analysis, sandbox queueing, and AI-assisted reporting are available in a dedicated lab view.</p>
        </div>
        <div class="card">
          <h2>Service Layer</h2>
          <p>Recon, malware, reporting, graph, and AI services are now separated from the legacy Flask wrapper.</p>
        </div>
      </div>
    </main>
  </div>
</body>
</html>
"""


WEB_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>ARCHAI X - Web Workspace</title>
  <style>
    body { margin: 0; font-family: Arial, sans-serif; background: #090d17; color: #eef6ff; }
    .layout { display: grid; grid-template-columns: 280px 1fr; min-height: 100vh; }
    .sidebar { padding: 24px; background: linear-gradient(180deg, #0d1324 0%, #090d17 100%); border-right: 1px solid #222f44; }
    .title { color: #8bf1ff; font-size: 1.3rem; font-weight: bold; }
    .nav a { display:block; padding:10px 12px; margin:8px 0; border-radius:10px; text-decoration:none; color:#dce8ff; border:1px solid transparent; }
    .nav a.active, .nav a:hover { border-color:#2e6bff; background: rgba(46, 107, 255, 0.12); }
    .content { padding: 24px; }
    .hero { border-radius: 18px; padding: 24px; background: linear-gradient(135deg, rgba(17, 28, 49, 0.98), rgba(8, 12, 22, 0.98)); border:1px solid #22335a; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap:16px; margin-top:18px; }
    .panel { background: rgba(11, 17, 29, 0.9); border:1px solid #24324b; border-radius:16px; padding:18px; }
    .panel h3 { margin-top:0; color: #8bf1ff; }
    .badge { display:inline-block; padding:4px 10px; border-radius:999px; font-size:0.85rem; background: rgba(90, 202, 255, 0.12); color:#8bf1ff; }
    .form-row { margin-top:12px; }
    input[type=text] { width: 100%; padding: 10px 12px; border-radius: 10px; border:1px solid #334767; background:#0d1324; color:#eff8ff; box-sizing:border-box; }
    button { margin-top: 12px; padding: 10px 14px; background: linear-gradient(90deg, #2e6bff, #3dd8ff); border:0; color:#fff; border-radius:10px; font-weight:700; cursor:pointer; }
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div class="title">Web Analysis</div>
      <p>Attack surface mapping and endpoint intelligence workspace</p>
      <div class="nav">
        <a href="/" class="active">Dashboard</a>
        <a href="/web">Recon Console</a>
        <a href="/malware">Malware Lab</a>
      </div>
    </aside>
    <main class="content">
      <div class="hero">
        <p class="badge">Recon & Intelligence Layer</p>
        <h1>Attack surface mapping console</h1>
        <p>Preserves masscan, nmap, whatweb, katana, gowitness, assetfinder, dalfox, sqlmap orchestration, AI reasoning, and graph generation.</p>
      </div>
      <div class="grid">
        <div class="panel">
          <h3>Live telemetry</h3>
          <p>Queue-aware scan execution, operational status, and telemetry streams can sit on top of the existing orchestrator.</p>
        </div>
        <div class="panel">
          <h3>Endpoint relationship graph</h3>
          <p>Attack path visualization and technology mapping are available to extend current graph outputs.</p>
        </div>
        <div class="panel">
          <h3>JS analysis pane</h3>
          <p>Endpoint and JS intelligence views are ready for integration with the crawling and scraping pipeline.</p>
        </div>
        <div class="panel">
          <h3>AI operator sidebar</h3>
          <p>The local AI reasoning layer remains intact and can be surfaced as a dedicated operator assistant.</p>
        </div>
      </div>
      <div class="panel" style="margin-top:18px;">
        <h3>Quick recon trigger</h3>
        <form method="get" action="/scan/scanme.nmap.org">
          <div class="form-row"><input type="text" name="target" placeholder="scanme.nmap.org" value="scanme.nmap.org" /></div>
          <button type="submit">Run preserved recon pipeline</button>
        </form>
      </div>
    </main>
  </div>
</body>
</html>
"""


MALWARE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>ARCHAI X - Malware Lab</title>
  <style>
    body { margin:0; font-family: Arial, sans-serif; background:#12070b; color:#fff1f2; }
    .layout { display:grid; grid-template-columns: 280px 1fr; min-height:100vh; }
    .sidebar { padding:24px; background: linear-gradient(180deg, #1b0e14 0%, #12070b 100%); border-right:1px solid #3b1b25; }
    .title { color:#ff909f; font-size:1.3rem; font-weight:bold; }
    .nav a { display:block; padding:10px 12px; margin:8px 0; border-radius:10px; text-decoration:none; color:#ffe1e8; border:1px solid transparent; }
    .nav a.active, .nav a:hover { border-color:#ff4d67; background: rgba(255, 77, 103, 0.14); }
    .content { padding:24px; }
    .hero { border-radius:18px; padding:24px; background: linear-gradient(135deg, rgba(42, 14, 22, 0.98), rgba(16, 4, 8, 0.98)); border:1px solid #451924; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap:16px; margin-top:18px; }
    .panel { background: rgba(17, 7, 11, 0.9); border:1px solid #4b1f2b; border-radius:16px; padding:18px; }
    .panel h3 { margin-top:0; color:#ff909f; }
    .badge { display:inline-block; padding:4px 10px; border-radius:999px; font-size:0.85rem; background: rgba(255, 77, 103, 0.15); color:#ffc1cb; }
    form { margin-top: 12px; }
    input[type=file] { width:100%; margin-top:8px; }
    button { margin-top:12px; padding:10px 14px; background: linear-gradient(90deg, #ff4d67, #ff8e6e); border:0; color:#fff; border-radius:10px; font-weight:700; cursor:pointer; }
    .danger-note { color:#ffd8de; }
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div class="title">Malware Lab</div>
      <p>Isolated analysis environment with safe ingestion and sandbox queueing</p>
      <div class="nav">
        <a href="/">Dashboard</a>
        <a href="/web">Web Workspace</a>
        <a href="/malware">Malware Lab</a>
      </div>
    </aside>
    <main class="content">
      <div class="hero">
        <p class="badge">Sandbox & Reverse Engineering</p>
        <h1>Isolated malware research workspace</h1>
        <p class="danger-note">Uploaded samples are quarantined, hashed, statically analyzed, and routed to a sandbox-only workflow. Host execution is never permitted.</p>
      </div>
      <div class="grid">
        <div class="panel">
          <h3>Upload Sample</h3>
          <p>Supports EXE, DLL, .NET binaries, PowerShell, Office docs, PDFs, and ZIP archives.</p>
          <form action="/api/malware/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" />
            <button type="submit">Quarantine + Analyze</button>
          </form>
        </div>
        <div class="panel">
          <h3>Static Analysis</h3>
          <p>SHA256, MD5, entropy, PE metadata, imports, IOC hints, and MITRE ATT&CK mapping are prepared in the service layer.</p>
        </div>
        <div class="panel">
          <h3>Dynamic Analysis</h3>
          <p>Disposable VM orchestration, fake internet simulation, telemetry collection, and auto-restore policies are modeled in the sandbox controller.</p>
        </div>
        <div class="panel">
          <h3>Reverse Engineering</h3>
          <p>Imports viewer, string references, function explorer, suspicious API highlighting, decompiler tabs, and .NET IL view hooks are ready for extension.</p>
        </div>
      </div>
    </main>
  </div>
</body>
</html>
"""


SCAN_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>ARCHAI X - Scan Results</title>
  <style>
    body { margin:0; font-family:Arial, sans-serif; background:#090c16; color:#eef6ff; }
    .container { padding:24px; }
    .card { border:1px solid #22335c; border-radius:16px; padding:20px; background: rgba(9, 14, 26, 0.96); }
    pre { white-space: pre-wrap; word-break: break-word; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>ARCHAI Recon Results</h1>
      <p>Target: {{ target }}</p>
      <pre>{{ data }}</pre>
    </div>
  </div>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HOME_TEMPLATE)


@app.route("/web")
def web_workspace():
    return render_template_string(WEB_TEMPLATE)


@app.route("/malware")
def malware_workspace():
    return render_template_string(MALWARE_TEMPLATE)


@app.route("/scan/<target>")
def scan(target):
    try:
        context = recon_service.scan_sync(target)
    except Exception as exc:
        return render_template_string(
            SCAN_TEMPLATE,
            target=target,
            data=f"Scan failed: {exc}",
        )

    return render_template_string(
        SCAN_TEMPLATE,
        target=target,
        data=json.dumps(context, indent=2, default=str),
    )


@app.route("/api/scan/<target>")
def api_scan(target):
    try:
        context = recon_service.scan_sync(target)
        return jsonify(context)
    except Exception as exc:
        return jsonify({"target": target, "error": str(exc)}), 500


@app.route("/api/malware/upload", methods=["POST"])
def upload_sample():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "file upload missing"}), 400

    metadata = sample_uploader.ingest(file.filename, file.read())
    static_analysis = static_analyzer.analyze(metadata)
    sandbox_job = sandbox_controller.create_job(metadata, "isolated")
    telemetry = telemetry_collector.collect(sandbox_job)
    ai_summary = malware_analyst.summarize(metadata, static_analysis, telemetry)

    return jsonify(
        {
            "metadata": metadata,
            "static_analysis": static_analysis,
            "sandbox_job": sandbox_job,
            "telemetry": telemetry,
            "ai_summary": ai_summary,
        }
    )


def run_dashboard():
    app.run(debug=True)
