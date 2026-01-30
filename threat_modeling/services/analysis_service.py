"""Analysis Service - Orchestration of LLM-based threat analysis and result formatting."""
import json
import pandas as pd
from typing import List, Dict, Optional

from ..api.llm_client import LLMClient
from ..api.message_builder import (
    generate_main_content,
    get_cot_message,
    get_few_shot_message,
    generate_messages
)
from ..config.settings import DATA_DIR
import os


class AnalysisService:
    """Service for running threat analysis (prompts, LLM calls) and building result DataFrames."""

    def __init__(self):
        """Initialize the analysis service."""
        pass
    
    def prepare_prompt_contents(self, system_description: str, few_shot: bool = False, 
                               cot: bool = False) -> List:
        """
        Prepare prompt contents based on options.
        
        Args:
            system_description: System description text
            few_shot: Include few-shot examples
            cot: Include chain of thoughts
            
        Returns:
            List of SystemMessage objects
        """
        prompt_contents = [generate_main_content(system_description)]
        
        if few_shot:
            prompt_contents.append(get_few_shot_message())
        
        if cot:
            prompt_contents.append(get_cot_message())
        
        return prompt_contents
    
    def run_analysis(self, interactions: List[Dict], system_description: str,
                     provider: str, model_name: str, few_shot: bool = False,
                     cot: bool = False, api_key: Optional[str] = None,
                     server_ip: Optional[str] = None, verbose: bool = False) -> List:
        """
        Run threat analysis on interactions.
        
        Args:
            interactions: List of interaction dictionaries
            system_description: System description
            provider: LLM provider ("OPENAI", "GOOGLE", "OLLAMA")
            model_name: Model name
            few_shot: Include few-shot examples
            cot: Include chain of thoughts
            api_key: API key for OpenAI/Google
            server_ip: Server IP for Ollama
            verbose: Print progress
            
        Returns:
            List of LLM results
        """
        # Prepare messages
        messages = generate_messages(interactions)
        prompt_contents = self.prepare_prompt_contents(system_description, few_shot, cot)
        
        # Create client and invoke
        client = LLMClient(provider=provider, model_name=model_name,
                          api_key=api_key, server_ip=server_ip)
        
        # Combine prompt contents with each message
        messages_list = []
        for message in messages:
            final_messages = prompt_contents.copy()
            final_messages.append(message)
            messages_list.append(final_messages)
        
        results = client.invoke_batch(messages_list, verbose=verbose)
        return results
    
    def generate_dataframe(self, interactions: List[Dict], results: List,
                          provider: str, model_name: str, save: bool = False,
                          path: Optional[str] = None) -> pd.DataFrame:
        """
        Generate DataFrame from analysis results.
        
        Args:
            interactions: List of interaction dictionaries
            results: List of LLM results
            provider: Provider name (for determining parsing method)
            model_name: Model name (for file naming)
            save: Whether to save to CSV
            path: Path to save CSV (optional)
            
        Returns:
            pandas DataFrame
        """
        rows = []
        
        for i, result in enumerate(results):
            try:
                if provider == "GOOGLE":
                    # Google returns structured output
                    content = result.model_dump()
                    message_rows = self._generate_rows_google(content, interactions[i])
                elif provider == "ANTHROPIC":
                    # Anthropic returns JSON strings similar to OpenAI
                    content = json.loads(result.content)
                    usage = getattr(result, 'usage_metadata', None) or getattr(result, 'response_metadata', {}).get('usage', {})
                    message_rows = self._generate_rows(content, interactions[i], usage)
                else:
                    # OpenAI/Ollama return JSON strings
                    content = json.loads(result.content)
                    usage = getattr(result, 'usage_metadata', None) or getattr(result, 'response_metadata', {}).get('usage', {})
                    message_rows = self._generate_rows(content, interactions[i], usage)
                
                rows.extend(message_rows)
            except Exception as e:
                print(f"Error processing result {i}: {str(e)}")
                continue
        
        df = pd.DataFrame(rows)
        
        if save:
            if path is None:
                path = f"{DATA_DIR}/analysis_{model_name}.csv"
            os.makedirs(os.path.dirname(path), exist_ok=True)
            df.to_csv(path, index=False)
        
        return df
    
    def _generate_rows(self, data: Dict, interaction: Dict, usage: Optional[Dict] = None) -> List[Dict]:
        """
        Build one row per threat from OpenAI/Anthropic/Ollama JSON response.

        Args:
            data: Parsed JSON with "threat_model" list (Category, Description, etc.).
            interaction: Single interaction dict (source, target, data_flow).
            usage: Optional token usage dict (input_tokens, output_tokens, total_tokens).

        Returns:
            List of row dicts for the DataFrame.
        """
        rows = []
        
        interaction_source = interaction['source']
        interaction_target = interaction['target']
        data_flow_name = interaction.get('data_flow', 'N/A')
        
        for threat in data.get('threat_model', []):
            nist_controls = threat.get('NIST_800_53_Controls', [])
            nist_controls += [None] * (3 - len(nist_controls))
            
            row = {
                'interaction_source': interaction_source,
                'interaction_target': interaction_target,
                'data_flow_name': data_flow_name,
                'category': threat.get('Category'),
                'description': threat.get('Description'),
                'justification': threat.get('Justification'),
                'potential_impact': threat.get('Potential Impact'),
                'nist_controls_1': nist_controls[0] if nist_controls[0] else None,
                'nist_controls_2': nist_controls[1] if nist_controls[1] else None,
                'nist_controls_3': nist_controls[2] if nist_controls[2] else None,
                'input_tokens': usage.get('input_tokens') if usage else None,
                'output_tokens': usage.get('output_tokens') if usage else None,
                'total_tokens': usage.get('total_tokens') if usage else None,
            }
            rows.append(row)
        
        return rows
    
    def _generate_rows_google(self, content: Dict, interaction: Dict) -> List[Dict]:
        """
        Build one row per threat from Google structured output (ThreatModel).

        Args:
            content: Model dump with "threat_model" list (Category, Description, Potential_Impact, etc.).
            interaction: Single interaction dict (source, target, data_flow).

        Returns:
            List of row dicts for the DataFrame.
        """
        rows = []
        
        interaction_source = interaction['source']
        interaction_target = interaction['target']
        data_flow_name = interaction.get('data_flow', 'N/A')
        
        for threat in content.get('threat_model', []):
            nist_controls = threat.get('NIST_800_53_Controls', [])
            nist_controls += [None] * (3 - len(nist_controls))
            
            row = {
                'interaction_source': interaction_source,
                'interaction_target': interaction_target,
                'data_flow_name': data_flow_name,
                'category': threat.get('Category'),
                'description': threat.get('Description'),
                'justification': threat.get('Justification'),
                'potential_impact': threat.get('Potential_Impact'),
                'nist_controls_1': nist_controls[0] if nist_controls[0] else None,
                'nist_controls_2': nist_controls[1] if nist_controls[1] else None,
                'nist_controls_3': nist_controls[2] if nist_controls[2] else None,
                'input_tokens': "",
                'output_tokens': "",
                'total_tokens': "",
            }
            rows.append(row)
        
        return rows

