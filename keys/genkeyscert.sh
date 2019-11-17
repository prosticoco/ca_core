#!/bin/bash
openssl req -new -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) -keyout server_private_key.key -out server_certificate.crt -days 3650
