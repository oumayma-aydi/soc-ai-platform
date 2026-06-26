FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-docker.txt .

# Installer torch CPU-only séparément avec un index isolé
# --index-url (pas --extra-index-url) = pip ne regarde QUE cet index pour cette commande
RUN pip install --no-cache-dir torch==2.12.0 --index-url https://download.pytorch.org/whl/cpu

# Installer le reste des dépendances normalement depuis PyPI
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY app/ ./app/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
