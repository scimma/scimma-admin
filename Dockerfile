FROM ubuntu:20.04

RUN apt-get update -y \
    && DEBIAN_FRONTEND="noninteractive" \
       apt-get install -y python3 \
                          python3-pip \
                          build-essential \
                          libpq-dev \
                          apache2 \
                          libapache2-mod-wsgi-py3

RUN ln -s /usr/bin/python3 /usr/bin/python
RUN pip3 install pip --upgrade
COPY ./requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt
COPY apache.conf /etc/apache2/sites-available/scimma_admin.conf
RUN a2dissite 000-default
RUN a2enmod wsgi md ssl
RUN a2ensite scimma_admin

COPY . /app
WORKDIR /app/scimma_admin
CMD apache2ctl -D FOREGROUND
