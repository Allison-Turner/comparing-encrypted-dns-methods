FROM ubuntu:latest

RUN /bin/bash -c 'apt-get --yes update; \
apt-get --yes install curl'

ENTRYPOINT ["/bin/bash"]
