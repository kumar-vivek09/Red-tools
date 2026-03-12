# ui/dashboard.py

from flask import Flask, render_template_string
from core.orchestrator import Orchestrator

app = Flask(__name__)

TEMPLATE = """
<html>
<head>
<title>ARCHAI Dashboard</title>
</head>
<body>
<h1>ARCHAI Scan Result</h1>
<pre>{{ data }}</pre>
</body>
</html>
"""


@app.route("/scan/<target>")
def scan(target):
    engine = Orchestrator(target)
    context = engine.run()
    return render_template_string(TEMPLATE, data=context)


def run_dashboard():
    app.run(debug=True)