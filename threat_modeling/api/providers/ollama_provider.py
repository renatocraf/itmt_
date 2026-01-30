"""Ollama provider - ChatOllama client for local models (JSON format)."""
from langchain_ollama import ChatOllama
from typing import Optional


def create_ollama_client(model_name: str, server_ip: Optional[str] = None) -> ChatOllama:
    """
    Create an Ollama ChatOllama client.
    
    Args:
        model_name: Name of the model to use
        server_ip: Base URL for Ollama server (optional, can use env var)
        
    Returns:
        ChatOllama instance configured for JSON output
    """
    return ChatOllama(
        model=model_name,
        base_url=server_ip,
        format="json"
    )

