FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY accounts.py pairing.py server.py streaming.py ./
ENV ROAMDESK_BIND=0.0.0.0 PORT=8080 PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
CMD ["python", "server.py"]
