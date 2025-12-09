#!/bin/bash

clean_docker () {
    container = $1
    output=$(docker ps -a -f name=$container | grep $container  2> /dev/null)
    if [ -n "$output" ]; then
	docker stop $container
	docker rm  $container
    fi
}

cleanup () {
    webpid=$(pgrep -f 'user_web_server.py')
    if [ -n "$webpid" ] ; then kill $webpid ; fi
    clean_docker scimma-admin-postgres
    clean_docker scimma-archive-postgres
}

trap cleanup EXIT

set -x

python user_web_server.py &

eval $(./config.sh local)

docker create --name scimma-admin-postgres \
       -e POSTGRES_DB=$ADMIN_DB_NAME \
       -e POSTGRES_PASSWORD=$ARCHIVE_DB_PASSWORD \
       -e POSTGRES_USER=$ADMIN_DB_USER \
       -p $ADMIN_DB_PORT:$ADMIN_DB_PORT
docker start scimma-admin-postgres
docker create --name scimma-archive-postgres \
       -e POSTGRES_DB=$ARCHIVE_DB_NAME \
       -e POSTGRES_PASSWORD=$ARCHIVE_DB_PASSWORD \
       -e POSTGRES_USER=$ARCHIVE_DB_USER \ \
       -p $ARCHIVE_DB_PORT:$ARCHIVE_DB_PORT
docker start scimma-admin-postgres

sleep 4

# cp scimma_admin/sample_local_settings.py scimma_admin/local_settings.py

echo yes | python scimma_admin/manage.py collectstatic
python scimma_admin/manage.py migrate

uwsgi --chdir=scimma_admin --module=scimma_admin.wsgi:application \
        --env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
        --pidfile=project-master.pid --http :8000 --processes 1 --threads 2
