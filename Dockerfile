FROM python:3.12-slim

RUN apt-get update -y \
    && apt-get install -y build-essential \
                          libpq-dev git

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

COPY . /app

WORKDIR /app/scimma_admin

RUN python manage.py collectstatic --noinput

RUN mkdir /root/.ssh && chmod 700 /root/.ssh

CMD /app/scripts/run --website
