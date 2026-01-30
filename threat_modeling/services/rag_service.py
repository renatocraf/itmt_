"""RAG Service - Retrieval Augmented Generation for NIST 800-53 controls."""
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings
from langchain_openai import OpenAIEmbeddings
from langchain_google_genai import GoogleGenerativeAIEmbeddings
import chromadb
import os
from typing import List, Optional

from ..models.rag_models import RAGResponse

# Anthropic doesn't have a dedicated embeddings service, so we'll skip it
# If needed in the future, we can use a workaround or third-party service

from ..config.settings import (
    RAG_CHROMA_HOST,
    RAG_CHROMA_PORT,
    RAG_CHROMA_SSL,
    RAG_COLLECTION_NAME,
    RAG_EMBEDDING_PROVIDER,
    RAG_EMBEDDING_MODEL,
    OLLAMA_URL,
    OPENAI_API_KEY,
    GOOGLE_API_KEY
)


class RAGService:
    """Service for RAG operations: ChromaDB similarity search and NIST control enhancement."""

    def __init__(self, provider: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initialize RAG service (embeddings and ChromaDB client are created lazily).

        Args:
            provider: Embedding provider ("OLLAMA", "OPENAI", "GOOGLE"). Default from config.
            api_key: API key for OpenAI/Google (optional; falls back to env vars).
        """
        self.provider = provider or RAG_EMBEDDING_PROVIDER
        self.api_key = api_key
        self._vector_store = None
    
    def _create_embeddings(self):
        """
        Create the embeddings instance for the configured provider.

        Returns:
            Embeddings instance (OllamaEmbeddings, OpenAIEmbeddings, or GoogleGenerativeAIEmbeddings).
        """
        if self.provider == "OLLAMA":
            return OllamaEmbeddings(
                model=RAG_EMBEDDING_MODEL,
                base_url=OLLAMA_URL if OLLAMA_URL else None
            )
        elif self.provider == "OPENAI":
            # Default OpenAI embedding model
            model = "text-embedding-ada-002"
            api_key = self.api_key or OPENAI_API_KEY
            return OpenAIEmbeddings(
                model=model,
                openai_api_key=api_key
            )
        elif self.provider == "GOOGLE":
            # Default Google embedding model
            model = "models/gemini-embedding-001"
            api_key = self.api_key or GOOGLE_API_KEY
            return GoogleGenerativeAIEmbeddings(
                model=model,
                google_api_key=api_key
            )
        else:
            raise ValueError(f"Unknown embedding provider: {self.provider}. Supported: OLLAMA, OPENAI, GOOGLE")
    
    def _get_collection_name(self) -> str:
        """
        Return ChromaDB collection name for the current embedding provider.

        Returns:
            Collection name (e.g. nist_controls_ollama, or from config).
        """
        provider_lower = self.provider.lower()
        collection_map = {
            "openai": "nist_controls_openai",
            "ollama": "nist_controls_ollama",
            "google": "nist_controls_google",
        }
        return collection_map.get(provider_lower, RAG_COLLECTION_NAME)

    def check_chromadb_connection(self) -> tuple[bool, str]:
        """
        Try to connect to ChromaDB (heartbeat). Use before running RAG to fail fast with a friendly message.

        Returns:
            Tuple (success: bool, error_message: str). If success is True, error_message is empty.
        """
        try:
            client = chromadb.HttpClient(
                host=RAG_CHROMA_HOST,
                port=RAG_CHROMA_PORT,
                ssl=RAG_CHROMA_SSL,
            )
            client.heartbeat()
            return True, ""
        except Exception as e:
            return False, str(e)
    
    def _get_vector_store(self) -> Chroma:
        """
        Get or create the Chroma vector store (lazy initialization).

        Returns:
            LangChain Chroma instance connected to the configured collection.
        """
        if self._vector_store is None:
            embeddings = self._create_embeddings()
            
            client = chromadb.HttpClient(
                host=RAG_CHROMA_HOST,
                port=RAG_CHROMA_PORT,
                ssl=RAG_CHROMA_SSL
            )
            
            collection_name = self._get_collection_name()
            
            self._vector_store = Chroma(
                client=client,
                collection_name=collection_name,
                embedding_function=embeddings,
            )
        
        return self._vector_store
    
    def search(self, query: str, k: int = 5) -> List:
        """
        Search for similar documents in the vector store.
        
        Args:
            query: Search query string
            k: Number of results to return
            
        Returns:
            List of document results
        """
        vector_store = self._get_vector_store()
        results = vector_store.similarity_search(query, k=k)
        return results
    
    def enhance_threats(self, threats_df, k: int = 5) -> List[str]:
        """
        Enhance threats with NIST recommendations using RAG.
        
        Args:
            threats_df: DataFrame with threats (must have 'category' and 'description' columns)
            k: Number of NIST controls to retrieve per threat
            
        Returns:
            List of RAG-enhanced text strings (one per threat)
        """
        rag_results = []
        
        for idx, row in threats_df.iterrows():
            category = row.get('category', '')
            description = row.get('description', '')
            question = f"{category}: {description}"
            
            try:
                results = self.search(question, k=k)
                # Join all results by title
                rag_text = ", ".join([doc.metadata.get('title', '') for doc in results])
                rag_results.append(rag_text)
            except Exception as e:
                print(f"Error processing threat {idx}: {str(e)}")
                rag_results.append("")
        
        return rag_results
    
    def parse_llm_response(self, rag_response: RAGResponse) -> str:
        """
        Parse RAGResponse Pydantic model and extract NIST controls.
        
        Args:
            rag_response: RAGResponse Pydantic model instance with validated NIST controls
            
        Returns:
            Semicolon-separated string of NIST controls, or empty string if list is empty
        """
        try:
            nist_controls = rag_response.nist_controls
            
            # Format as semicolon-separated string
            if isinstance(nist_controls, list) and len(nist_controls) > 0:
                controls_text = "; ".join(str(control) for control in nist_controls)
            else:
                controls_text = ""
            
            return controls_text
            
        except Exception as e:
            print(f"Error processing RAGResponse: {str(e)}")
            # Return empty string on error
            return ""

