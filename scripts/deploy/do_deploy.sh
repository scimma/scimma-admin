#!/bin/bash

set -euo pipefail

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
run_preflight_checks

say_green "building docker container"
docker_build 1>/dev/null

say_green "logging in to ECR registry"
docker_login 1>/dev/null 2>/dev/null

say_green "pushing docker image"
docker_push 1>/dev/null

say_green "rolling out new docker image"
kubectl rollout restart deployment/hopdevel-scimma-admin
