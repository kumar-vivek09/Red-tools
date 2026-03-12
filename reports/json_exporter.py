# reports/json_exporter.py

import json
import os
from datetime import datetime


def export_json(context):

    os.makedirs("reports", exist_ok=True)

    filename = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(context, f, indent=4)

    return filename