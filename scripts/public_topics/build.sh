!/bin/bash
# convenience to build a container named dlp-test so as to not clobber
# any producion tags.
set -x
export VERSION=dlp-test
export IMAGE_TAG=dlp-test
../deploy/release.sh

