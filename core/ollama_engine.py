import json
import os

import requests


def generate_ai_report(data):

    prompt = f"""
You are a cybersecurity expert.

Analyze the following scan results and generate a professional penetration testing summary.

Data:
{json.dumps(data, indent=2)}

Give:
1. Attack surface summary
2. Possible vulnerabilities
3. Risk level (Low/Medium/High)
4. Attack graph
5. Recommended actions
"""

    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3")

    try:
        response = requests.post(
            f"{base_url.rstrip('/')}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
            },
            timeout=30,
        )

        result = response.json()
        return result["response"]

    except Exception as e:
        return f"AI Error: {str(e)}"