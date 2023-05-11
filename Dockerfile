FROM python:3.10-slim-buster

RUN apt update
WORKDIR /app
ADD requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

ADD app /app/app
ADD sql_db.db /app/sql_db.db

#ENV PORT 8080
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8000"]
