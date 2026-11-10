FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copies only the app modules in this folder; tests live in tests/ and stay out.
COPY *.py ./
# Don't run as root inside the container.
USER nobody
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
