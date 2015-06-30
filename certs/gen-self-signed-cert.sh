#!/bin/bash
openssl genrsa -out responder.key 2048
openssl req -new -x509 -days 3650 -key responder.key -out responder.crt -subj "/"
