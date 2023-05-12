FROM python:3.10-slim-buster

RUN apt update
WORKDIR /app
ADD requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

ADD app /app/app
ADD config.py /app/config.py

# inject these env vars via GKE configmap
ENV LOG_LEVEL DEBUG
ENV RESET_DB True
ENV OAUTH2_URL_BASE "http://127.0.0.1:8080"

# the cmd list mode does NOT interpret env var
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8080"]
