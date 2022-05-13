#!/usr/bin/env bash

run_doh_test(){
    DOMAIN=$1
    TYPE=$2
    
    # ensuring no interference from other containers
    docker stop $(docker ps -a -q)

    docker build -t doh-test-env -f DOH-Dockerfile .
    wait

    dumpcap -i docker0 --autostop duration:10 -n -q &

    CONTAINER_ID=$(docker run -dit doh-test-env)
    docker exec $CONTAINER_ID curl -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name='$DOMAIN'&type='$TYPE
    wait
}

declare -a domains=("google.com" "ucsd.edu" "cdc.gov")

for i in "${domains[@]}"
do
   run_doh_test "$i" 'A'
   run_doh_test "$i" 'AAAA'
done
