#!/usr/bin/env bash

# ensuring no interference from other containers
docker stop $(docker ps -a -q)

docker build -t doq-test-env -f DOQ-Dockerfile .
wait

#CLIENT_CONTAINER_ID=$(docker run -dit doq-test-env)
#wait

#PROXY_CONTAINER_ID=$(docker run -dit doq-test-env)
#wait

#declare -a domains=("google.com" "ucsd.edu" "cdc.gov")
