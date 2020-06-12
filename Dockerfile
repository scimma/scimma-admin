FROM python:3.8-slim-buster

RUN apt-get update -y \
    && apt-get install -y build-essential \
                          libpq-dev

COPY . /app
WORKDIR /app/scimma_admin

RUN pip install -r /app/requirements.txt
CMD gunicorn scimma_admin.wsgi:application --bind 0.0.0.0:8000
