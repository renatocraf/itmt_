
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

import chromadb

# 3. Embeddings
embeddings = HuggingFaceEmbeddings(
    model_name="Qwen/Qwen3-Embedding-0.6B",
    model_kwargs={"device": "cuda"},
    encode_kwargs={"normalize_embeddings": True}
)



client = chromadb.HttpClient(host="192.168.5.100", port=8002, ssl=False)

vector_store_from_client = Chroma(
    client=client,
    collection_name="nist_controls_summarized",
    embedding_function=embeddings,
)

