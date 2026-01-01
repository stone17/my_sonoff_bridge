FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app

# Create a volume point for config
RUN mkdir /config

# Point the app to look for config here (requires changing main.py path)
ENV CONFIG_PATH=/config/config.yaml

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]