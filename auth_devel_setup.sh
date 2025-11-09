#!/bin/bash

container=scimma-admin-postgres

cleanup () {
    webpid=$(pgrep -f 'user_web_server.py')
    if [ -n "$webpid" ] ; then kill $webpid ; fi 
    output=$(docker ps -a -f name=$container | grep $container  2> /dev/null)
      if [ -n "$output" ]; then
       docker stop $container
       docker rm  $container
    fi
}

trap cleanup EXIT

set -x

python user_web_server.py &

docker create --name scimma-admin-postgres \
       -e POSTGRES_DB=postgres \
       -e POSTGRES_PASSWORD=postgres \
       -e POSTGRES_USER=postgres \
       -p 5432:5432 postgres
docker start scimma-admin-postgres
docker create --name scimma-archive-postgres \
       -e POSTGRES_DB=postgres \
       -e POSTGRES_PASSWORD=postgres \
       -e POSTGRES_USER=postgres \
       -p 5432:5433 postgres
docker start scimma-admin-postgres

eval $(./config.sh local)

cp scimma_admin/sample_local_settings.py scimma_admin/local_settings.py

sleep 4

python scimma_admin/manage.py migrate

uwsgi --chdir=scimma_admin --module=scimma_admin.wsgi:application \
        --env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
        --pidfile=project-master.pid --http :8000 --processes 1 --threads 2
