# ITA Threat Modeling Tool (ITA TMT)

Automated threat analysis using AI to process Microsoft Threat Modeling Tool (.tm7) files and produce structured security analyses with STRIDE classification and NIST 800-53 control suggestions.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Docker](#docker)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Supported Models](#supported-models)
- [Security](#security)
- [License](#license)

## Overview

ITA TMT is a **Flask** web application that:

- **Parses** .tm7 files (Microsoft Threat Modeling Tool) into diagrams, data flows, and threats
- **Analyzes** interactions with one of several **LLM providers** (OpenAI, Google Gemini, Anthropic Claude, or Ollama) to classify threats (STRIDE) and suggest mitigations
- **Optionally enriches** results with **RAG** using a ChromaDB NIST 800-53 knowledge base
- **Compares** tool-generated threats with AI-generated threats (similar / TMT-only / AI-only)
- **Exports** results as JSON or CSV

## Features

- **.tm7 parsing**: Extract diagrams, elements, data flows, trust boundaries, and threats; support for multiple diagrams per file
- **Multi-provider LLM analysis**: OpenAI, Google, Anthropic, Ollama; select provider and model in the UI; API key per session
- **Prompt options**: Zero-shot, few-shot examples, chain-of-thought (configurable in analysis form)
- **RAG enhancement**: Semantic search in NIST controls (ChromaDB); optional step after analysis to add recommended NIST controls per threat
- **Comparison**: Compare threats from the TMT tool with AI analysis (similarity score and explanation via LLM)
- **Downloads**: Analysis and RAG results as JSON/CSV; comparison as CSV

## Requirements

- Python 3.8+
- For cloud providers: OpenAI and/or Google and/or Anthropic API keys
- For local LLM: [Ollama](https://ollama.com/) (optional)
- For RAG: ChromaDB (e.g. Docker service or standalone server)

## Installation

```bash
git clone <repository-url>
cd itmt_
pip install -r requirements.txt
```

Create a `.env` file from the template (see [Configuration](#configuration)).

## Configuration

Copy `example_env` to `.env` and adjust:

```env
# API keys (only for providers you use)
OPENAI_API_KEY=
GOOGLE_API_KEY=
# ANTHROPIC_API_KEY=   # optional; can be set in the web UI

# Ollama (local models)
OLLAMA_URL=http://localhost:11434

# Flask
FLASK_SECRET_KEY=change-me-in-production
# PORT=5000
# HOST=127.0.0.1
# FLASK_DEBUG=False

# RAG (ChromaDB)
# RAG_CHROMA_HOST=localhost
# RAG_CHROMA_PORT=8000
# RAG_CHROMA_SSL=false
# RAG_COLLECTION_NAME=nist_controls_summarized
# RAG_EMBEDDING_PROVIDER=OLLAMA
# RAG_EMBEDDING_MODEL=qwen3-embedding:4b
```

- **API keys**: Required only for the provider you choose in the UI (OpenAI, Google, or Anthropic). Ollama does not need an API key.
- **Flask**: Set a strong `FLASK_SECRET_KEY` in production.
- **RAG**: Required only if you use the “RAG enhance” feature; ChromaDB must be running and the NIST collection must exist.

## Usage

### Run the web application

```bash
python run_flask.py
```

Or, using Flask’s CLI (with `app` in `app.py`):

```bash
export FLASK_APP=app.py
flask run
```

By default the server listens on `127.0.0.1:5000`. Set `HOST` and `PORT` in `.env` if needed (e.g. `HOST=0.0.0.0` for external access).

Open `http://localhost:5000` in your browser.

### Typical workflow

1. **Upload**: On the home page, upload a .tm7 file and provide a system description.
2. **Diagram**: If the file has multiple diagrams, choose which one to analyze.
3. **Analyze**: On the analysis page, select provider, enter API key (if required), choose model, and optionally enable few-shot and chain-of-thought. Run the analysis.
4. **Results**: View the threat analysis table; optionally run **RAG enhance** to add NIST controls, or open **Compare** to see TMT vs AI threat comparison.
5. **Download**: Use the download links to export JSON or CSV (analysis, RAG-enhanced, or comparison).

## Docker

Build and run with Docker Compose (app + ChromaDB):

```bash
docker-compose up --build
```

The app is exposed on port **9007** (mapped from container port 5000). ChromaDB is on port 8000. Set `OPENAI_API_KEY`, `GOOGLE_API_KEY`, and optionally `OLLAMA_HOST` in the environment or in a `.env` file next to `docker-compose.yaml`.

To run only the app (without docker-compose):

```bash
docker build -t ita-tmt .
docker run -p 5000:5000 -e OPENAI_API_KEY=your_key ita-tmt
```

## Project Structure

```
itmt_/
├── app.py                 # Flask app entry for "flask run"
├── run_flask.py           # Main entry: creates app and runs server
├── requirements.txt
├── Dockerfile
├── docker-compose.yaml
├── example_env            # Environment template
├── blocks/                # Prompt templates (main_content, few-shot, CoT, json_output)
└── threat_modeling/
    ├── config/settings.py # Configuration from environment
    ├── models/            # Threat model dataclasses, TM7 parser, Pydantic (RAG, comparison)
    ├── api/               # LLM client, message builder, model lister, providers
    ├── services/          # Threat model, analysis, RAG, comparison services
    ├── web/               # Flask app factory, routes, forms, templates
    └── static/            # CSS, JS
```

For a detailed description of layers and data flows, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## Documentation

- **[ARCHITECTURE.md](./ARCHITECTURE.md)** — Architecture overview, components, data flows, configuration, and dependencies.

## Supported Models

- **OpenAI**: Any chat model listed by the API (e.g. gpt-4, gpt-4o, o1-*).
- **Google**: Gemini models listed by the API (e.g. gemini-2.0-flash).
- **Anthropic**: Claude models (e.g. claude-3-5-sonnet, claude-3-opus); see `threat_modeling.api.model_lister`.
- **Ollama**: Any model you run locally (e.g. llama3, qwen3:8b, gemma3:12b). Configure `OLLAMA_URL` if Ollama is not on localhost.

## Security

- Store API keys in environment variables or `.env`; do not commit them.
- Use a strong `FLASK_SECRET_KEY` in production.
- File uploads are limited (e.g. 16MB) and restricted to .tm7.
- Session cookies are HttpOnly and SameSite Lax.

## License

This project is a research proof-of-concept from ITA (Instituto Tecnológico de Aeronáutica). See [LICENSE](./LICENSE) for details.
