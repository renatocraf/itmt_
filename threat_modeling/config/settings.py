"""Configuration settings for the Threat Modeling Tool (env-based)."""
import os


# API Keys
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

# Provider Configuration
# Options: "OPENAI", "GOOGLE", "OLLAMA"
DEFAULT_PROVIDER = "OLLAMA"

# Available Models
MODELS = [
    # lower medium class
    "gemma3:27b",
    "qwen3:30b",
    "gpt-oss:20b",
    # lower class
    "gemma3:12b",
    "qwen3:8b",
    "mistral:7b",
]

DEFAULT_MODEL = MODELS[4]  # qwen3:8b

# RAG Configuration
RAG_CHROMA_HOST = os.getenv("RAG_CHROMA_HOST", "localhost")
RAG_CHROMA_PORT = int(os.getenv("RAG_CHROMA_PORT", "8000"))
RAG_CHROMA_SSL = os.getenv("RAG_CHROMA_SSL", "false").lower() == "true"
RAG_COLLECTION_NAME = os.getenv("RAG_COLLECTION_NAME", "nist_controls_summarized")
RAG_EMBEDDING_PROVIDER = os.getenv("RAG_EMBEDDING_PROVIDER", "OLLAMA")  # Options: "OLLAMA", "OPENAI", "GOOGLE"
RAG_EMBEDDING_MODEL = os.getenv("RAG_EMBEDDING_MODEL", "qwen3-embedding:4b")

# Data paths
DATA_DIR = "./data"
BLOCKS_DIR = "./blocks"

