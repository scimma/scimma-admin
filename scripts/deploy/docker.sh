#!/bin/bash

docker_build() {
    docker build --tag scimma-admin-web .
}

docker_login() {
    aws ecr \
        get-login-password \
        --region us-west-2 \
        | docker login \
                 --username AWS \
                 --password-stdin 585193511743.dkr.ecr.us-west-2.amazonaws.com
}

docker_push() {
    docker tag scimma-admin-web 585193511743.dkr.ecr.us-west-2.amazonaws.com/scimma-admin-web
    docker push 585193511743.dkr.ecr.us-west-2.amazonaws.com/scimma-admin-web:latest
}
