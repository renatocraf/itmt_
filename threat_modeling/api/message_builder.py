"""Message Builder - Build system and user messages for analysis, RAG, and comparison prompts."""
from langchain_core.messages import SystemMessage, HumanMessage
from typing import List, Dict
import os


def get_message_from_file(path: str) -> str:
    """
    Read text content from a file.

    Args:
        path: Path to the file (e.g. blocks/main_content.txt).

    Returns:
        File contents as a string (UTF-8).
    """
    with open(path, 'r', encoding='utf-8') as file:
        return file.read()


def get_blocks_dir() -> str:
    """
    Return the blocks directory path (prompt templates).

    Returns:
        Path from BLOCKS_DIR env var, or "./blocks" if unset.
    """
    return os.getenv("BLOCKS_DIR", "./blocks")


def generate_main_content(system_desc: str) -> SystemMessage:
    """
    Generate main content system message with system description.
    
    Args:
        system_desc: System description to include in the prompt
        
    Returns:
        SystemMessage with main content and system description
    """
    blocks_dir = get_blocks_dir()
    main_content_text = get_message_from_file(f'{blocks_dir}/main_content.txt')
    json_output_text = get_message_from_file(f'{blocks_dir}/json_output.txt')
    
    return SystemMessage(
        main_content_text + f"\n\n{system_desc}\n" + json_output_text
    )


def get_cot_message() -> SystemMessage:
    """
    Return the Chain-of-Thought system message from blocks/cot.txt.

    Returns:
        SystemMessage with CoT instructions.
    """
    blocks_dir = get_blocks_dir()
    cot_text = get_message_from_file(f'{blocks_dir}/cot.txt')
    return SystemMessage(cot_text)


def get_few_shot_message() -> SystemMessage:
    """
    Return the Few-Shot examples system message from blocks/fs.txt.

    Returns:
        SystemMessage with few-shot examples.
    """
    blocks_dir = get_blocks_dir()
    fs_text = get_message_from_file(f'{blocks_dir}/fs.txt')
    return SystemMessage(fs_text)


def generate_question(interaction_information: str) -> str:
    """
    Generate question prompt for a single interaction.
    
    Args:
        interaction_information: Formatted interaction details
        
    Returns:
        Formatted question string
    """
    question = f'''### INTERACTION TO ANALYZE:

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


def generate_messages(interactions: List[Dict]) -> List[HumanMessage]:
    """
    Generate HumanMessage list from interactions.
    
    Args:
        interactions: List of interaction dictionaries with keys:
                     - source
                     - data_flow
                     - target
                     - trust_boundaries
                     
    Returns:
        List of HumanMessage objects
    """
    messages = []
    for interaction in interactions:
        source = interaction['source']
        data_flow = interaction['data_flow']
        target = interaction['target']
        trust_boundaries = interaction['trust_boundaries']
        
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


def generate_system_prompt_rag() -> SystemMessage:
    """
    Generate system prompt for RAG enhancement.
    
    Returns:
        SystemMessage with RAG instructions
    """
    system_prompt = """You are a cybersecurity expert analyzing threats and recommending NIST controls.
Given a threat description and relevant NIST controls retrieved from a knowledge base, identify which NIST controls are most relevant and commonly used to mitigate this specific threat.

Provide a concise response listing the most relevant NIST control titles that should be applied to address this threat.
Answer MUST BE an JSON in this format:
{
    "nist_controls": [
        "NIST Control 1",
        "NIST Control 2",
        "NIST Control 3"
    ]
}
"""
    
    return SystemMessage(content=system_prompt)


def format_rag_documents(rag_docs: List) -> str:
    """
    Format RAG documents for inclusion in prompt.
    
    Args:
        rag_docs: List of document objects from RAG search
        
    Returns:
        Formatted string with document titles and contents
    """
    rag_content = []
    for doc in rag_docs:
        title = doc.metadata.get('title', '')
        content = doc.page_content if hasattr(doc, 'page_content') else ''
        rag_content.append(f"Title: {title}\nContent: {content}")
    
    return "\n\n".join(rag_content)


def generate_user_prompt_rag(category: str, description: str, rag_text: str) -> str:
    """
    Generate user prompt for RAG enhancement.
    
    Args:
        category: Threat category (STRIDE)
        description: Threat description
        rag_text: Formatted RAG documents text
        
    Returns:
        Formatted user prompt string
    """
    user_prompt = f"""Threat Category: {category}
Threat Description: {description}

Relevant NIST Controls Retrieved:
{rag_text}

Based on the threat information above and the NIST controls retrieved, which NIST controls are most relevant and commonly used to mitigate this threat? Please list only the control titles, separated by commas."""
    
    return user_prompt


def generate_rag_messages(category: str, description: str, rag_docs: List) -> List:
    """
    Generate complete message list for RAG enhancement.
    
    Args:
        category: Threat category (STRIDE)
        description: Threat description
        rag_docs: List of document objects from RAG search
        
    Returns:
        List of messages [SystemMessage, HumanMessage] ready for LLM invocation
    """
    system_message = generate_system_prompt_rag()
    rag_text = format_rag_documents(rag_docs)
    user_prompt = generate_user_prompt_rag(category, description, rag_text)
    user_message = HumanMessage(content=user_prompt)
    
    return [system_message, user_message]


def generate_system_prompt_comparison() -> SystemMessage:
    """
    Generate system prompt for threat comparison.
    
    Returns:
        SystemMessage with comparison instructions
    """
    system_prompt = """You are a cybersecurity expert analyzing and comparing threat descriptions.
Given two threat descriptions from different sources (TMT threat modeling tool and AI analysis), determine if they describe the same or similar security threat.

Your task is to:
1. Analyze both threat descriptions carefully
2. Determine if they describe the same or similar security concern
3. Provide a similarity score between 0.0 (completely different) and 1.0 (identical)
4. Explain your reasoning clearly

Consider:
- Core security concern (what vulnerability/attack is being described)
- Attack vector or method
- Potential impact
- Affected components or data flows

Two threats should be considered similar if they address the same core security issue, even if the wording or specific details differ.

Answer MUST BE a JSON in this format:
{
    "is_similar": true,
    "similarity_score": 0.85,
    "explanation": "Brief explanation of why they are similar or different"
}
"""
    
    return SystemMessage(content=system_prompt)


def generate_user_prompt_comparison(tmt_description: str, ai_description: str, category: str, dataflow_name: str) -> str:
    """
    Generate user prompt for threat comparison.
    
    Args:
        tmt_description: Threat description from TMT tool
        ai_description: Threat description from AI analysis
        category: Threat category (STRIDE)
        dataflow_name: Name of the dataflow
        
    Returns:
        Formatted user prompt string
    """
    user_prompt = f"""Compare these two threat descriptions for the same dataflow and category:

DataFlow Name: {dataflow_name}
Category: {category}

TMT Threat Description:
{tmt_description}

AI Analysis Threat Description:
{ai_description}

Are these two descriptions referring to the same or similar security threat? Provide your analysis."""
    
    return user_prompt


def generate_comparison_messages(tmt_description: str, ai_description: str, category: str, dataflow_name: str) -> List:
    """
    Generate complete message list for threat comparison.
    
    Args:
        tmt_description: Threat description from TMT tool
        ai_description: Threat description from AI analysis
        category: Threat category (STRIDE)
        dataflow_name: Name of the dataflow
        
    Returns:
        List of messages [SystemMessage, HumanMessage] ready for LLM invocation
    """
    system_message = generate_system_prompt_comparison()
    user_prompt = generate_user_prompt_comparison(tmt_description, ai_description, category, dataflow_name)
    user_message = HumanMessage(content=user_prompt)
    
    return [system_message, user_message]

