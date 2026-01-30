FROM python:3.12-slim

# Define o diretório de trabalho
WORKDIR /app

# Copia os arquivos de requisitos
COPY requirements.txt .

# Instala as dependências Python
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /app/data
RUN mkdir -p /app/blocks

# Copia a aplicação Flask
COPY run_flask.py .
COPY threat_modeling ./threat_modeling
COPY blocks ./blocks

# Comando para executar a aplicação Flask
ENV HOST=0.0.0.0
ENV PORT=5000
EXPOSE 5000
ENTRYPOINT ["python", "run_flask.py"]