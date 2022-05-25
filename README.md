# comparing-encrypted-dns-methods

## Example runs

If you do not need sudo to run Docker commands on your machine, and you want to your user own the artifacts generated 
```
whoami | run-encrypted-dns-tests.sh
```

If you do need sudo to run Docker commands, and you want a user called "susie.queue" to own the artifacts generated
```
sudo ./run-encrypted-dns-tests.sh susie.queue
```
