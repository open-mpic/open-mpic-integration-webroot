#!/usr/bin/env bash
openssl req -x509 -out tls-alpn.integration-testing.open-mpic.org.crt -nodes -days 36500 -config tls-alpn-01-valid-cert.cnf

