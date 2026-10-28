"""
Gemini LLM factory (preloaded).

Returns a ready-to-use crewai.LLM connected to Google Gemini through CrewAI's native provider (built on
the google-genai SDK). The model name and API key always come from the .env file — never hardcoded — so
associates choose their own model via GEMINI_MODEL.
"""

from crewai import LLM

from core.config import config


def get_llm(temperature: float = 0.2, max_tokens: int = 2000) -> LLM:
    """Return a Gemini LLM using the model and key from the .env file."""
    return LLM(
        model=f"gemini/{config.gemini_model}",
        api_key=config.gemini_api_key,
        temperature=temperature,
        max_tokens=max_tokens,
    )
