#from dotenv import load_dotenv
import os
#load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
# os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY 

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
# os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY 

# ========= SELECT YOUR PROVIDER =========
PROVIDER = "OLLAMA"   # Options: "OPENAI", "GOOGLE", "OLLAMA"
# ========================================

models = [
    # lower medium class
    "gemma3:27b",
    "qwen3:30b",
    "gpt-oss:20b",
    # lower class
    "gemma3:12b",
    "qwen3:8b",
    "mistral:7b",
    ]

DEFAULT_MODEL = models[4]

OLLAMA_URL = os.getenv("OLLAMA_URL")