#!/bin/bash

ssh -i scimma-admin-web-deploy.pem ec2-user@admin.dev.hop.scimma.org '/bin/bash -c "
$(aws ecr get-login --no-include-email --region us-west-2)
docker pull 585193511743.dkr.ecr.us-west-2.amazonaws.com/scimma-admin-web:latest
docker stop scimma-admin-web
docker run --rm \
           --env SCIMMA_ADMIN_PROD=yes \
           --publish 80:8000 \
           --name scimma-admin-web \
           585193511743.dkr.ecr.us-west-2.amazonaws.com/scimma-admin-web:latest
"'
