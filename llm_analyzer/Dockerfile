FROM python:3.10-slim

WORKDIR /app

# 安裝連線 Postgres 必備的 psycopg2-binary
RUN pip install flask flask-cors aisuite[all] mistralai openai groq psycopg2-binary

COPY app.py .

CMD ["python", "app.py"]