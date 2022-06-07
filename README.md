# comparing-encrypted-dns-methods

## Requirements & Dependencies
* Docker
* dumpcap
* PyShark
* bash shell
* internet access
* https://github.com/ameshkov/dnslookup
  * potential for https://github.com/ns1labs/doq-proxy , but could not get docker-compose inter-container networking config working   
* https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/

## Example runs

If you do not need sudo to run Docker commands on your machine, and you want to your user own the artifacts generated 
```
whoami | run-encrypted-dns-tests.sh
```

If you do need sudo to run Docker commands, and you want a user called "susie.queue" to own the artifacts generated
```
sudo ./run-encrypted-dns-tests.sh susie.queue
```
