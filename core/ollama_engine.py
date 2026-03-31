import requests
import json

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
4. Recommended actions
"""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3",
                "prompt": prompt,
                "stream": False
            }
        )

        result = response.json()
        return result["response"]

    except Exception as e:
        return f"AI Error: {str(e)}"