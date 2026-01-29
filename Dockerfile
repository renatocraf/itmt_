FROM python:3.12-slim

# Define o diretório de trabalho
WORKDIR /app

# Instala dependências do sistema
#RUN apt-get update && apt-get install -y \
#    build-essential \
#    software-properties-common \
#    && rm -rf /var/lib/apt/lists/*

# Copia os arquivos de requisitos
COPY requirements.txt .

# Instala as dependências Python
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /app/data
RUN mkdir -p /app/blocks


COPY ./*.py .
COPY ./blocks ./blocks


# Configurações de healthcheck
#HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Comando para executar a aplicação
ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]