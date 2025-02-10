#!/bin/bash

if [[ $# -ge 1 && "$1" == "--ssl" ]]; then
    python3 hosts/HTTPServer/manage.py runserver_plus --cert-file .ssh/cert.pem --key-file .ssh/key.pem 10.0.1.1:443
else
    python3 hosts/HTTPServer/manage.py runserver 10.0.1.1:80
fi


