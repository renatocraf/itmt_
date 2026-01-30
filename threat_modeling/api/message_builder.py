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
    blocks_dir = get_blocks_dir()
    template = get_message_from_file(f'{blocks_dir}/question_interaction.txt')
    return template.format(interaction_information=interaction_information)


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
    blocks_dir = get_blocks_dir()
    interaction_template = get_message_from_file(f'{blocks_dir}/interaction_format.txt')
    
    messages = []
    for interaction in interactions:
        organized_interaction = interaction_template.format(
            source=interaction['source'],
            data_flow=interaction['data_flow'],
            target=interaction['target'],
            trust_boundaries=interaction['trust_boundaries']
        )
        
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
    blocks_dir = get_blocks_dir()
    system_prompt = get_message_from_file(f'{blocks_dir}/rag_system.txt')
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
    blocks_dir = get_blocks_dir()
    template = get_message_from_file(f'{blocks_dir}/rag_user.txt')
    return template.format(
        category=category,
        description=description,
        rag_text=rag_text
    )


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
    blocks_dir = get_blocks_dir()
    system_prompt = get_message_from_file(f'{blocks_dir}/comparison_system.txt')
    fs_comparison = get_message_from_file(f'{blocks_dir}/fs_comparison.txt')
    
    return SystemMessage(content=system_prompt + "\n\n" + fs_comparison)


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
    blocks_dir = get_blocks_dir()
    template = get_message_from_file(f'{blocks_dir}/comparison_user.txt')
    return template.format(
        dataflow_name=dataflow_name,
        category=category,
        tmt_description=tmt_description,
        ai_description=ai_description
    )


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

