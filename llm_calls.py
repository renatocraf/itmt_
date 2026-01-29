from langchain_core.messages import SystemMessage, HumanMessage

# Providers
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama
from pydantic import BaseModel

import json
import pandas as pd

from config import (
    DEFAULT_MODEL,
    OLLAMA_URL,
    PROVIDER,
    
)


def load_interactions(path='interaction.json'):
    with open (path, 'r') as file:
        return json.loads(file.read())
    
def get_message_from_file(path):  
    with open(path, 'r') as file:
        return file.read()

main_content = SystemMessage(get_message_from_file('./blocks/main_content.txt') + get_message_from_file('./blocks/json_output.txt'))
cot = SystemMessage(get_message_from_file('./blocks/cot.txt'))
fs = SystemMessage(get_message_from_file('./blocks/fs.txt'))

def generate_main_content(system_desc):
    return SystemMessage(
        get_message_from_file('./blocks/main_content.txt') + \
        f"\n\n{system_desc}" + \
        get_message_from_file('./blocks/json_output.txt')) 
    

class Threat(BaseModel):
    Category : str
    Description : str
    Justification : str
    Potential_Impact : str
    NIST_800_53_Controls : list[str]
    
class ThreatModel(BaseModel):
    threat_model : list[Threat]


def get_model(provider: str, model_name=DEFAULT_MODEL, api_key=None, server_ip=None):
    """Return a LangChain LLM instance based on provider name."""
    if provider == "OPENAI":
        return ChatOpenAI(
            model=model_name,
            model_kwargs={"response_format": {"type": "json_object"}},
            api_key=api_key
        )

    elif provider == "GOOGLE":
        llm = ChatGoogleGenerativeAI(
            model=model_name,
            api_key=api_key
        )
        return llm.with_structured_output(ThreatModel)

    elif provider == "OLLAMA":
        return ChatOllama(
            model=model_name,
            base_url=server_ip,
            format="json"
            )

    else:
        raise ValueError(f"Unknown provider: {provider}")  
    
def generate_question(interaction_information):
          
    question =  f'''### INTERACTION TO ANALYZE:

{interaction_information}

-----

### Instructions

Analyze the single interaction defined in the `INTERACTION TO ANALYZE` section. Use the `OVERALL APPLICATION CONTEXT` to understand its place in the system and potential risks. Then, follow these steps:

1.  Check if have relevant threats in this interaction, and classify those with STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
2.  Each threat scenario must clearly describe how the threat could occur in the context of this specific interaction.
3.  For each threat, include the potential impact it may have on the system, data, or stakeholders.
4.  For each threat, suggest how it can be mitigated.
5.  For each threat, suggest maximum of 3 relevant NIST 800-53 security controls that could mitigate or reduce the risk.
6.  It's not mandatory to suggests threats, so do not force.

'''

    return question

def generate_messages(interactions):
    messages = []
    for interaction in interactions:
      print(interaction)
      source = interaction['source']
      data_flow = interaction['data_flow']
      target = interaction['target']
      trust_boundaries = interaction['trust_boundaries']
    #   interaction_context = interaction['context']
    
      organized_interaction = f'''Interaction:
        Source: {source}
        Data Flow: {data_flow}
        Target: {target}
        Trust Boundary: {trust_boundaries}
          '''
    
      question = generate_question(organized_interaction)
      
      message = HumanMessage(question)
      messages.append(message)

    return messages

def generate_rows(data, interaction, usage):
    rows = []
    
    interaction_source = interaction['source']
    interaction_target = interaction['target']
    
    for threat in data['threat_model']:
        nist_controls = threat.get('NIST_800_53_Controls', [])
        nist_controls += [None] * (3 - len(nist_controls))
        row = {
            'interaction_source': interaction_source,
            'interaction_target': interaction_target,
            'category': threat.get('Category'),
            'description': threat.get('Description'),
            'justification': threat.get('Justification'),
            'potential_impact': threat.get('Potential Impact'),
            'nist_controls_1': nist_controls[0] if nist_controls[0] else None,
            'nist_controls_2': nist_controls[1] if nist_controls[1] else None,
            'nist_controls_3': nist_controls[2] if nist_controls[2] else None,
            'input_tokens': usage.get('input_tokens'),
            'output_tokens': usage.get('output_tokens'),
            'total_tokens': usage.get('total_tokens'),
        }
        rows.append(row)

    return rows


def call_API_for_results(messages, prompt_contents, provider=PROVIDER, model_name=DEFAULT_MODEL, verbose=False, api_key=None, server_ip=None):
    results = []
    
    for i, message in enumerate(messages):
        if verbose:
            print(f"Generating Results for Message {i+1}")
        final_message = prompt_contents.copy()
        final_message.append(message)
        model = get_model(provider, model_name, api_key=api_key, server_ip=server_ip)   
        result = model.invoke(final_message)
        results.append(result)   
    return results
        

def generate_dataframe(interactions, results, save=False, path = './data/model.csv'):

    rows = []
    for i, result in enumerate(results):
        try:        
            content = json.loads(result.content)    
            message_rows = generate_rows(content, interactions[i], result.usage_metadata)
            
            rows = rows + message_rows
        except:
            print(f"Erro detectado em {i}, continuando")
    df = pd.DataFrame(rows)
    if save:
        df.to_csv(path)
    return df

def generate_dataframe_google(interactions, results, save=False, path = './data/model.csv'):
    rows = []
    for i, result in enumerate(results):
        try:        
            content = results[i].model_dump()    
            
            message_rows = []
            interaction_source = interactions[i]['source']
            interaction_target = interactions[i]['target']
            
            for threat in content['threat_model']:
                nist_controls = threat.get('NIST_800_53_Controls', [])
                nist_controls += [None] * (3 - len(nist_controls))
                row_threat = {
                    'interaction_source': interaction_source,
                    'interaction_target': interaction_target,
                    'category': threat.get('Category'),
                    'description': threat.get('Description'),
                    'justification': threat.get('Justification'),
                    'potential_impact': threat.get('Potential_Impact'),
                    'nist_controls_1': nist_controls[0] if nist_controls[0] else None,
                    'nist_controls_2': nist_controls[1] if nist_controls[1] else None,
                    'nist_controls_3': nist_controls[2] if nist_controls[2] else None,
                    'input_tokens': "",
                    'output_tokens': "",
                    'total_tokens':"",
                }
                print(row_threat)
                message_rows.append(row_threat)
            
            rows = rows + message_rows
        except:
            print(f"Erro detectado em {i}, continuando")
    df = pd.DataFrame(rows)
    if save:
        df.to_csv(path)
    return df


















