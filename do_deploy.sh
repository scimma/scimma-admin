#!/bin/bash

docker-compose -f production.yml build
docker-compose -f production.yml push
ssh -i scimma-admin-web-deploy.pem ec2-user@admin.dev.hop.scimma.org "/bin/bash -c '
$(aws ecr get-login --no-include-email --region us-west-2)
docker pull 585193511743.dkr.ecr.us-west-2.amazonaws.com/scimma-admin-web:latest

docker run --rm \
           --env DJANGO_SETTINGS_MODULE=config.settings.production \
           --publish 80:8080 \
           585193511743.dkr.ecr.us-west-2.amazonaws.com/scimma-admin-web:latest \
           /start
'"
