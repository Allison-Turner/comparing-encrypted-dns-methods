FROM ubuntu:latest

RUN /bin/bash -c 'apt-get --yes update; \
apt-get --yes install git; \
apt-get --yes install golang; \
apt-get --yes install make; \
git clone https://github.com/ameshkov/dnslookup.git'

WORKDIR "/dnslookup/"

RUN /bin/bash -c 'make'

ENTRYPOINT ["/bin/bash"]