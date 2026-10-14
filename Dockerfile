FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt requirements-lock.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c requirements-lock.txt && useradd --uid 10001 --create-home edl && mkdir /data && chown edl:edl /data
COPY . .
USER 10001:10001
ENV EDL_CONFIG=/data/config.json PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python", "run_service.py", "web"]
