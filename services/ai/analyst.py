"""AI analysis helpers for the ARCHAI X platform."""

from core.ollama_engine import generate_ai_report


class AIAnalyst:
    """Wrap local Ollama-driven reasoning for security summaries."""

    def summarize(self, payload):
        try:
            return generate_ai_report(payload)
        except Exception:
            return "AI analysis unavailable. Configure Ollama to enable local LLM summarization."
