"""LLM Client - Abstract interface for multi-provider LLM calls."""
from typing import List, Optional, Type, TypeVar
from langchain_core.messages import BaseMessage
from pydantic import BaseModel

from .providers.openai_provider import create_openai_client
from .providers.google_provider import create_google_client
from .providers.ollama_provider import create_ollama_client
from .providers.anthropic_provider import create_anthropic_client
from ..config.settings import DEFAULT_MODEL, DEFAULT_PROVIDER

T = TypeVar('T', bound=BaseModel)


class LLMClient:
    """Client for LLM API calls (OpenAI, Google, Anthropic, Ollama) with optional structured output."""

    def __init__(self, provider: str = DEFAULT_PROVIDER, model_name: str = DEFAULT_MODEL,
                 api_key: Optional[str] = None, server_ip: Optional[str] = None):
        """
        Initialize LLM client for the given provider and model.

        Args:
            provider: Provider name ("OPENAI", "GOOGLE", "ANTHROPIC", "OLLAMA").
            model_name: Model identifier (e.g. gpt-4o, gemini-2.0-flash, claude-3-5-sonnet, qwen3:8b).
            api_key: API key for cloud providers (optional; uses env vars if not set).
            server_ip: Base URL for Ollama (optional; uses OLLAMA_URL from env if not set).
        """
        self.provider = provider
        self.model_name = model_name
        self.api_key = api_key
        self.server_ip = server_ip
        self._model = None
    
    def _get_model(self):
        """Return the underlying LangChain model (lazy initialization)."""
        if self._model is None:
            if self.provider == "OPENAI":
                self._model = create_openai_client(self.model_name, self.api_key)
            elif self.provider == "GOOGLE":
                self._model = create_google_client(self.model_name, self.api_key)
            elif self.provider == "ANTHROPIC":
                self._model = create_anthropic_client(self.model_name, self.api_key)
            elif self.provider == "OLLAMA":
                self._model = create_ollama_client(self.model_name, self.server_ip)
            else:
                raise ValueError(f"Unknown provider: {self.provider}")
        return self._model
    
    def _get_base_model(self):
        """Return the base model without structured output (for invoke_with_structure fallback)."""
        from langchain_core.runnables import RunnableSequence
        
        model = self._get_model()
        
        # If model is already a RunnableSequence (has structured output), get base model
        if isinstance(model, RunnableSequence):
            # For Google provider, create a new base model without structured output
            if self.provider == "GOOGLE":
                from .providers.google_provider import create_google_client
                return create_google_client(self.model_name, self.api_key, with_structure=False)
            # For other providers, try to get the first step (base model)
            # This is a fallback - may not work for all cases
            if hasattr(model, 'steps') and len(model.steps) > 0:
                return model.steps[0]
        
        return model
    
    def invoke(self, messages: List[BaseMessage]):
        """
        Invoke the LLM with a list of messages.
        
        Args:
            messages: List of BaseMessage objects (SystemMessage, HumanMessage, etc.)
            
        Returns:
            LLM response
        """
        model = self._get_model()
        return model.invoke(messages)
    
    def invoke_batch(self, messages_list: List[List[BaseMessage]], verbose: bool = False) -> List:
        """
        Invoke the LLM for multiple message sets.
        
        Args:
            messages_list: List of message lists (one per interaction)
            verbose: If True, print progress
            
        Returns:
            List of LLM responses
        """
        results = []
        model = self._get_model()
        
        for i, messages in enumerate(messages_list):
            if verbose:
                print(f"Generating Results for Message {i+1}")
            result = model.invoke(messages)
            results.append(result)
        
        return results
    
    def invoke_with_structure(self, messages: List[BaseMessage], pydantic_model: Type[T]) -> T:
        """
        Invoke the LLM with structured output using Pydantic model.
        
        This method uses LangChain's with_structured_output to ensure the response
        matches the provided Pydantic model, providing type safety and validation
        across different providers.
        
        Args:
            messages: List of BaseMessage objects (SystemMessage, HumanMessage, etc.)
            pydantic_model: Pydantic BaseModel class to structure the response
            
        Returns:
            Instance of the Pydantic model with validated data
            
        Raises:
            ValueError: If the response cannot be parsed into the Pydantic model
        """
        from langchain_core.runnables import RunnableSequence
        
        model = self._get_model()
        
        # Check if model already has structured output applied (is a RunnableSequence)
        if isinstance(model, RunnableSequence):
            # Get base model without structured output
            base_model = self._get_base_model()
        else:
            base_model = model
        
        try:
            # Apply structured output to the base model
            structured_model = base_model.with_structured_output(pydantic_model)
            
            # Invoke with structured output
            result = structured_model.invoke(messages)
            
            return result
            
        except Exception as e:
            # Fallback: try to parse manually if structured output fails
            print(f"Warning: Structured output failed, attempting manual parsing: {str(e)}")
            try:
                raw_response = base_model.invoke(messages)
                
                # Extract content from response
                if hasattr(raw_response, 'content'):
                    response_text = raw_response.content
                else:
                    response_text = str(raw_response)
                
                # Try to parse JSON and create Pydantic model
                import json
                import re
                
                # Remove markdown code blocks if present
                cleaned_text = re.sub(r'```json\s*', '', response_text)
                cleaned_text = re.sub(r'```\s*', '', cleaned_text)
                cleaned_text = cleaned_text.strip()
                
                # Extract JSON object
                json_match = re.search(r'\{.*?\}', cleaned_text, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    json_str = cleaned_text
                
                # Parse JSON and create Pydantic model
                if json_str:
                    response_dict = json.loads(json_str)
                    return pydantic_model(**response_dict)
                else:
                    raise ValueError("Empty response from LLM")
                
            except Exception as parse_error:
                raise ValueError(
                    f"Failed to parse LLM response into {pydantic_model.__name__}: {str(parse_error)}"
                ) from e

