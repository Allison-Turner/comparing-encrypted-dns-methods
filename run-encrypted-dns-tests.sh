#!/usr/bin/env bash

FILE_OWNER=$1

if [ -z "$FILE_OWNER" ];
then
    echo "Please include the name of the user who should own the generated network monitoring artifacts"
    echo "You can check your username with the whoami command"
    exit(1)
fi

HELPER_LOG="./helper.log"

DOT_PCAP_DIR="./dot-pcaps"
DOT_OUTFILE_DIR="./dot-outfiles"

DOH_PCAP_DIR="./doh-pcaps"
DOH_OUTFILE_DIR="./doh-outfiles"

DOQ_PCAP_DIR="./doq-pcaps"
DOQ_OUTFILE_DIR="./doq-outfiles"

TS=$(date +"%Y-%m-%d-%H-%M-%S")

declare -a domains=("google.com" "bing.com" "ucsd.edu" "cdc.gov" "fda.gov" "louvre.fr" "narendramodi.in" "bu.edu" "uw.edu" "af.mil" "marines.mil" "army.mil" "npr.org")
#declare -a domains=("google.com")

init(){
    if [ ! -f "$HELPER_LOG" ]; then
        touch $HELPER_LOG
        chown $FILE_OWNER $HELPER_LOG
    fi

    if [ ! -d "$DOT_PCAP_DIR" ]; then
        mkdir "$DOT_PCAP_DIR"
        chown $FILE_OWNER $DOT_PCAP_DIR
    fi

    if [ ! -d "$DOT_OUTFILE_DIR" ]; then
        mkdir "$DOT_OUTFILE_DIR"
        chown $FILE_OWNER $DOT_OUTFILE_DIR
    fi

    if [ ! -d "$DOH_PCAP_DIR" ]; then
        mkdir "$DOH_PCAP_DIR"
        chown $FILE_OWNER $DOH_PCAP_DIR
    fi

    if [ ! -d "$DOH_OUTFILE_DIR" ]; then
        mkdir "$DOH_OUTFILE_DIR"
        chown $FILE_OWNER $DOH_OUTFILE_DIR
    fi

    if [ ! -d "$DOQ_PCAP_DIR" ]; then
        mkdir "$DOQ_PCAP_DIR"
        chown $FILE_OWNER $DOQ_PCAP_DIR
    fi

    if [ ! -d "$DOQ_OUTFILE_DIR" ]; then
        mkdir "$DOQ_OUTFILE_DIR"
        chown $FILE_OWNER $DOQ_OUTFILE_DIR
    fi
}

start_packet_capture(){
    DURATION=$1
    FILE=$(dumpcap -i docker0 --autostop duration:$DURATION -n -q 2>&1 >/dev/null | grep "File:" | awk '{print $2}')
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

run_dot_test(){
    DOMAIN=$1
    TYPE=$2
    TIMESTAMP=$3
    OUTFILE="$DOT_OUTFILE_DIR/$DOMAIN-$TYPE-$TIMESTAMP.out"

    echo "DOT: '$TYPE' record query on domain '$DOMAIN'"

    touch $OUTFILE

    CONTAINER_ID=$(docker run -dit adguard-dnslookup-env)
    wait

    sleep 5
    start_packet_capture 15 &
    sleep 2
    docker exec $CONTAINER_ID /bin/bash -c "export RRTYPE=$TYPE && ./dnslookup $DOMAIN tls://dns.adguard.com" >> $OUTFILE 2>&1
    wait
    chown $FILE_OWNER $OUTFILE

    remove_test_container $CONTAINER_ID

    move_pcap_to_result_dir $DOT_PCAP_DIR 'dot' $i $TYPE $TIMESTAMP

    echo "Test finished"
}

run_doh_test(){
    DOMAIN=$1
    TYPE=$2
    TIMESTAMP=$3
    OUTFILE="$DOH_OUTFILE_DIR/$DOMAIN-$TYPE-$TIMESTAMP.out"

    echo "DOH: '$TYPE' record query on domain '$DOMAIN'"

    touch $OUTFILE

    CONTAINER_ID=$(docker run -dit curl-cloudflare-resolver-env)
    wait

    sleep 5
    start_packet_capture 15 &
    sleep 2
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

    CONTAINER_ID=$(docker run -dit adguard-dnslookup-env)
    wait

    sleep 5
    start_packet_capture 15 &
    sleep 2
    docker exec $CONTAINER_ID /bin/bash -c "export RRTYPE=$TYPE && ./dnslookup $DOMAIN quic://dns.adguard.com" >> $OUTFILE 2>&1
    wait
    chown $FILE_OWNER $OUTFILE

    remove_test_container $CONTAINER_ID

    move_pcap_to_result_dir $DOQ_PCAP_DIR 'doq' $i $TYPE $TIMESTAMP

    echo "Test finished"
}

run_persistent_env_dot_tests(){
    TIMESTAMP=$1
    OUTFILE="$DOT_OUTFILE_DIR/persistent-env-dot-$TIMESTAMP.out"

    echo "DOT: A + AAAA queries in persistent environment on following domains:"
    for i in "${domains[@]}"
    do
        echo $i
    done

    touch $OUTFILE

    CONTAINER_ID=$(docker run -dit adguard-dnslookup-env)
    wait

    DURATION=$(( ${#domains[@]}*5 ))
    start_packet_capture $DURATION &

    for i in "${domains[@]}"
    do
        docker exec $CONTAINER_ID /bin/bash -c "export RRTYPE=A && ./dnslookup $i tls://dns.adguard.com" >> $OUTFILE 2>&1

        docker exec $CONTAINER_ID /bin/bash -c "export RRTYPE=AAAA && ./dnslookup $i tls://dns.adguard.com" >> $OUTFILE 2>&1
    done

    wait

    chown $FILE_OWNER $OUTFILE

    remove_test_container $CONTAINER_ID

    move_pcap_to_result_dir $DOT_PCAP_DIR 'dot' 'persistent-env' 'A-AAAA' $TIMESTAMP

    echo "Test finished"
}

run_persistent_env_doh_tests(){
    TIMESTAMP=$1
    OUTFILE="$DOH_OUTFILE_DIR/persistent-env-doh-$TIMESTAMP.out"

    echo "DOH: A + AAAA queries in persistent environment on following domains:"
    for i in "${domains[@]}"
    do
        echo $i
    done

    touch $OUTFILE

    CONTAINER_ID=$(docker run -dit curl-cloudflare-resolver-env)
    wait

    DURATION=$(( ${#domains[@]}*5 ))
    start_packet_capture $DURATION &

    for i in "${domains[@]}"
    do
        docker exec $CONTAINER_ID curl -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name='$i'&type=A' >> $OUTFILE 2>&1

        docker exec $CONTAINER_ID curl -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name='$i'&type=AAAA' >> $OUTFILE 2>&1
    done
       
    wait

    chown $FILE_OWNER $OUTFILE

    remove_test_container $CONTAINER_ID

    move_pcap_to_result_dir $DOH_PCAP_DIR 'doh' 'persistent-env' 'A-AAAA' $TIMESTAMP

    echo "Test finished"
}

run_persistent_env_doq_tests(){
    TIMESTAMP=$1
    OUTFILE="$DOQ_OUTFILE_DIR/persistent-env-doq-$TIMESTAMP.out"

    echo "DOQ: A + AAAA queries in persistent environment on following domains:"
    for i in "${domains[@]}"
    do
        echo $i
    done

    touch $OUTFILE

    CONTAINER_ID=$(docker run -dit adguard-dnslookup-env)
    wait

    DURATION=$(( ${#domains[@]}*5 ))
    start_packet_capture $DURATION &

    for i in "${domains[@]}"
    do
        docker exec $CONTAINER_ID /bin/bash -c "export RRTYPE=A && ./dnslookup $i quic://dns.adguard.com" >> $OUTFILE 2>&1

        docker exec $CONTAINER_ID /bin/bash -c "export RRTYPE=AAAA && ./dnslookup $i quic://dns.adguard.com" >> $OUTFILE 2>&1
    done

    wait

    chown $FILE_OWNER $OUTFILE

    remove_test_container $CONTAINER_ID

    move_pcap_to_result_dir $DOQ_PCAP_DIR 'doq' 'persistent-env' 'A-AAAA' $TIMESTAMP

    echo "Test finished"
}

init
wait

docker stop $(docker ps -a -q)
wait

docker build -t curl-cloudflare-resolver-env -f cloudflare-rest-api-via-curl-env.Dockerfile .
docker build -t adguard-dnslookup-env -f adguard-dnslookup-env.Dockerfile .
wait

#for i in "${domains[@]}"
#do
#    run_dot_test $i 'A' $TS
#    wait
#
#    run_dot_test $i 'AAAA' $TS
#    wait
#
#    run_doh_test $i 'A' $TS
#    wait
#
#    run_doh_test $i 'AAAA' $TS
#    wait
#
#    run_doq_test $i 'A' $TS
#    wait
#
#    run_doq_test $i 'AAAA' $TS
#    wait
#done

run_persistent_env_dot_tests $TS
run_persistent_env_doh_tests $TS
run_persistent_env_doq_tests $TS
