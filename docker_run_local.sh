#!/bin/bash

docker run \
       --rm \
       --volume $PWD:/app \
       -it \
       585193511743.dkr.ecr.us-west-2.amazonaws.com/scimma-admin \
       /usr/local/bin/python /app/scimma_admin/manage.py runserver
