#!/bin/bash

set -eo pipefail

SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
source "${SCRIPT_DIR}/preflight.sh"
source "${SCRIPT_DIR}/docker.sh"

say_green() {
    local GREEN='\033[0;32m'
    local NO_COLOR='\033[0m'
    printf "${GREEN}$1${NO_COLOR}\n" 1>&2
}

cd $SCRIPT_DIR/../../

say_green "running preflight checks"
check_for_docker
check_for_aws

if [ -z "$VERSION" ]; then
    VERSION=$(git describe --tags --abbrev=0)
    echo "Inferred image version is $VERSION"
else
    echo "Configured image version is $VERSION"
fi

say_green "building docker container"
docker_build "$VERSION" 1>/dev/null

say_green "logging in to ECR registry"
docker_login 1>/dev/null 2>/dev/null

say_green "pushing docker image"
docker_push "$VERSION" 1>/dev/null
