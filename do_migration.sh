#!/bin/bash

ssh -i scimma-admin-web-deploy.pem ec2-user@admin.dev.hop.scimma.org '/bin/bash -c "
docker exec scimma-admin-web python /app/scimma-admin/manage.py migrate
"'
