#!/bin/bash
openssl genrsa -des3 -out responder.tmp.key 2048&&openssl rsa -in responder.tmp.key -out responder.key&&openssl req -new -key responder.key -out responder.csr&&openssl x509 -req -days 365 -in responder.csr -signkey responder.key -out responder.crt&&rm responder.tmp.key responder.csr
