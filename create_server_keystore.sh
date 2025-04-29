#!/bin/bash

# Password for server keystore
PASS=123456

# Create server keystore directory if it doesn't exist
mkdir -p ../ssl

# Generate server keypair and self-signed certificate
keytool -genkeypair \
    -alias myCienciasServer \
    -keyalg RSA \
    -keysize 2048 \
    -validity 365 \
    -keystore server.keystore \
    -storepass $PASS \
    -keypass $PASS \
    -dname "CN=myCienciasServer,OU=Departamento de Informatica,O=Faculdade de Ciencias,C=PT"

# Export server certificate
keytool -exportcert \
    -alias myCienciasServer \
    -file server.cer \
    -keystore server.keystore \
    -storepass $PASS

# Create truststore for clients
keytool -importcert \
    -alias myCienciasServer \
    -file server.cer \
    -keystore truststore.jks \
    -storepass $PASS \
    -noprompt

# Copy keystores to ssl directory
cp server.keystore ../ssl/
cp truststore.jks ../ssl/

echo "Server keystore and truststore created successfully!" 