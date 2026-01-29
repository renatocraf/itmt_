from llm_calls import *

main_content = SystemMessage(get_message_from_file('./blocks/main_content.txt') + get_message_from_file('./blocks/json_output.txt'))
cot = SystemMessage(get_message_from_file('./blocks/cot.txt'))
fs = SystemMessage(get_message_from_file('./blocks/fs.txt'))

interactions = load_interactions()
messages = generate_messages(interactions)

provider = PROVIDER

# Open Weights Models
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

# ZERO SHOT
prompt_contents = [main_content]
for model_name in models:    
# model_name = models[4]
    print(f"Starting {model_name}")    
    results = call_API_for_results(messages[0:], prompt_contents, provider, model_name, False)    
    df = generate_dataframe(interactions, results, True, f"./data/ZS/{model_name}.csv")
    
# FEW SHOT
prompt_contents = [main_content, fs]
for model_name in models:    
# model_name = models[4]
    print(f"Starting {model_name}")    
    results = call_API_for_results(messages[0:], prompt_contents, provider, model_name, False)    
    df = generate_dataframe(interactions, results, True, f"./data/FS/{model_name}.csv")    

# Paid Models - API - ZS
provider = PROVIDER
model_name = "gpt-4.1-nano"
prompt_contents = [main_content]
print(f"Starting {model_name}")    
results = call_API_for_results(messages[0:], prompt_contents, provider, model_name, False)    
df = generate_dataframe(interactions, results, True, f"./data/ZS/{model_name}.csv")


# Paid Models - API -ZS
provider = "GOOGLE"
model_name = "gemini-2.5-flash"
prompt_contents = [main_content]
print(f"Starting {model_name}")    
results = call_API_for_results(messages[0:], prompt_contents, provider, model_name, True)    
df = generate_dataframe_google(interactions, results, True, f"./data/ZS/{model_name}.csv")

# Paid Models - API - FS
provider = "OPENAI"
model_name = "gpt-4.1-nano"
prompt_contents = [main_content, fs]
print(f"Starting {model_name}")    
results = call_API_for_results(messages[0:], prompt_contents, provider, model_name, False)    
df = generate_dataframe(interactions, results, True, f"./data/FS/{model_name}.csv")

# Paid Models - API -FS
provider = "GOOGLE"
model_name = "gemini-2.5-flash"
prompt_contents = [main_content, fs]
print(f"Starting {model_name}")    
results = call_API_for_results(messages[0:], prompt_contents, provider, model_name, False)    
df = generate_dataframe_google(interactions, results, True, f"./data/FS/{model_name}.csv")