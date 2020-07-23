FROM python:3.8-slim-buster

RUN apt-get update -y \
    && apt-get install -y build-essential \
                          libpq-dev

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

COPY . /app

WORKDIR /app/scimma_admin
CMD uwsgi --chdir=/app/scimma_admin \
    --module=scimma_admin.wsgi:application \
    --env DJANGO_SETTINGS_MODULE=scimma_admin.settings \
    --master --pidfile=/tmp/project-master.pid \
    --http :80 \
    --processes 4 \
    --threads 2
