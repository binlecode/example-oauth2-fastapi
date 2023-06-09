FROM python:3.10-slim-buster

RUN apt update
WORKDIR /app
ADD requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

ADD app /app/app
ADD config.py /app/config.py

# authz endpoints url base for localhost env
# ENV OAUTH2_URL_BASE "http://127.0.0.1:8080"
# ENV LOG_LEVEL "INFO"

# the cmd list mode does NOT interpret env var
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8080"]
