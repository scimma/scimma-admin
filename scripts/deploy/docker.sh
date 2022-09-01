#!/bin/bash

docker_build() {
    if [ $# -eq 1 ]; then
        IMAGE_TAG="$1"
    fi
    docker build --tag scimma-admin-web:"$IMAGE_TAG" .
    echo "  Built scimma-admin-web:$IMAGE_TAG" 1>&2
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
    if [ $# -eq 1 ]; then
        IMAGE_TAG="$1"
    fi
    docker tag scimma-admin-web:"$IMAGE_TAG" 585193511743.dkr.ecr.us-west-2.amazonaws.com/scimma-admin-web:"$IMAGE_TAG"
    docker push 585193511743.dkr.ecr.us-west-2.amazonaws.com/scimma-admin-web:"$IMAGE_TAG"
}
