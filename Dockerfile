FROM python:3.8-slim-buster

RUN apt-get update -y \
    && apt-get install -y build-essential \
                          libpq-dev

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

COPY . /app

WORKDIR /app/scimma_admin
CMD gunicorn scimma_admin.wsgi:application --bind 0.0.0.0:8000
