FROM python:3.8-slim-buster

RUN apt-get update -y \
    && apt-get install -y build-essential \
                          libpq-dev

COPY . /app
WORKDIR /app

RUN pip install -r /app/requirements.txt

CMD
