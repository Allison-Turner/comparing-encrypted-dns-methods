#!/usr/bin/env bash

FILE_OWNER=$1

HELPER_LOG="./helper.log"
DOH_PCAP_DIR="./doh-pcaps"
DOQ_PCAP_DIR="./doq-pcaps"
DOH_OUTFILE_DIR="./doh-outfiles"
DOQ_OUTFILE_DIR="./doq-outfiles"

TS=$(date +"%Y-%m-%d-%H-%M-%S")

#declare -a domains=("google.com" "bing.com" "ucsd.edu" "cdc.gov" "fda.gov" "louvre.fr" "narendramodi.in" "bu.edu" "uw.edu" "af.mil" "marines.mil" "army.mil" "npr.org")
declare -a domains=("google.com")

init(){
    if [ ! -f "$HELPER_LOG" ]; then
        touch $HELPER_LOG
        chown $FILE_OWNER $HELPER_LOG
    fi

    if [ ! -d "$DOH_PCAP_DIR" ]; then
        mkdir "$DOH_PCAP_DIR"
        chown $FILE_OWNER $DOH_PCAP_DIR
    fi

    if [ ! -d "$DOQ_PCAP_DIR" ]; then
        mkdir "$DOQ_PCAP_DIR"
        chown $FILE_OWNER $DOQ_PCAP_DIR
    fi

    if [ ! -d "$DOH_OUTFILE_DIR" ]; then
        mkdir "$DOH_OUTFILE_DIR"
        chown $FILE_OWNER $DOH_OUTFILE_DIR
    fi

    if [ ! -d "$DOQ_OUTFILE_DIR" ]; then
        mkdir "$DOQ_OUTFILE_DIR"
        chown $FILE_OWNER $DOQ_OUTFILE_DIR
    fi
}

start_packet_capture(){
    FILE=$(dumpcap -i docker0 --autostop duration:10 -n -q 2>&1 >/dev/null | grep "File:" | awk '{print $2}')
    echo $FILE > $HELPER_LOG
}

remove_test_container(){
    CONTAINER_ID=$1

    docker stop $CONTAINER_ID
    wait
    docker rm -f $CONTAINER_ID
    wait  
}

move_pcap_to_result_dir(){
    RESULT_DIR=$1
    ENCRYPTED_DNS_TYPE=$2
    DOMAIN=$3
    RRTYPE=$4
    TIMESTAMP=$5

    ORIG_FILEPATH=$(cat $HELPER_LOG)
    ORIG_FILENAME=$(basename $ORIG_FILEPATH)
    EXTENSION=$(echo "${ORIG_FILENAME##*.}")
    MOVED_FILEPATH="$RESULT_DIR/$ORIG_FILENAME"
    NEW_FILENAME="$ENCRYPTED_DNS_TYPE-$DOMAIN-$RRTYPE-$TIMESTAMP.$EXTENSION"
    NEW_FILEPATH="$RESULT_DIR/$NEW_FILENAME"

    mv $ORIG_FILEPATH $RESULT_DIR
    mv $MOVED_FILEPATH $NEW_FILEPATH
    chown $FILE_OWNER $NEW_FILEPATH
    wait
}

run_doh_test(){
    DOMAIN=$1
    TYPE=$2
    TIMESTAMP=$3
    OUTFILE="$DOH_OUTFILE_DIR/$DOMAIN-$TYPE-$TIMESTAMP.out"

    echo "DOH: '$TYPE' record query on domain '$DOMAIN'"

    touch $OUTFILE

    CONTAINER_ID=$(docker run -dit doh-env)
    wait

    sleep 1
    start_packet_capture &
    sleep 1
    docker exec $CONTAINER_ID curl -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name='$DOMAIN'&type='$TYPE >> $OUTFILE 2>&1
    wait
    chown $FILE_OWNER $OUTFILE

    remove_test_container $CONTAINER_ID

    move_pcap_to_result_dir $DOH_PCAP_DIR 'doh' $i $TYPE $TIMESTAMP

    echo "Test finished"
}

run_doq_test(){
    DOMAIN=$1
    TYPE=$2
    TIMESTAMP=$3
    OUTFILE="$DOQ_OUTFILE_DIR/$DOMAIN-$TYPE-$TIMESTAMP.out"

    echo "DOQ: '$TYPE' record query on domain '$DOMAIN'"

    touch $OUTFILE

    CONTAINER_ID=$(docker run -dit doq-env)
    wait

    sleep 1
    start_packet_capture &
    sleep 1
    docker exec $CONTAINER_ID /bin/bash -c "export RRTYPE=$TYPE && ./dnslookup $DOMAIN quic://dns.adguard.com" >> $OUTFILE 2>&1
    wait
    chown $FILE_OWNER $OUTFILE

    remove_test_container $CONTAINER_ID

    move_pcap_to_result_dir $DOQ_PCAP_DIR 'doq' $i $TYPE $TIMESTAMP

    echo "Test finished"
}

init
wait

docker stop $(docker ps -a -q)
wait

docker build -t doh-env -f doh-env.Dockerfile .
docker build -t doq-env -f doq-env.Dockerfile .
wait

for i in "${domains[@]}"
do
    run_doh_test $i 'A' $TS
    wait

    run_doh_test $i 'AAAA' $TS
    wait

    run_doq_test $i 'A' $TS
    wait

    run_doq_test $i 'AAAA' $TS
    wait
done