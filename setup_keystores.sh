#!/bin/bash

# Password for all keystores
PASS=123456

# Create certificates directory if it doesn't exist
mkdir -p ../certificates

# Create keystores for test users
for user in silva maria joao ana; do
    # Generate key pair
    keytool -genkeypair \
        -alias $user \
        -keyalg RSA \
        -keysize 2048 \
        -dname "CN=$user" \
        -validity 365 \
        -storetype PKCS12 \
        -keystore $user.keystore \
        -storepass $PASS \
        -keypass $PASS

    # Export certificate
    keytool -exportcert \
        -alias $user \
        -file $user.cer \
        -keystore $user.keystore \
        -storepass $PASS
        
    # Copy certificate to the certificates directory
    cp $user.cer ../certificates/
done

# Import certificates into each keystore
for user1 in silva maria joao ana; do
    for user2 in silva maria joao ana; do
        if [ "$user1" != "$user2" ]; then
            keytool -importcert \
                -alias $user2 \
                -file $user2.cer \
                -keystore $user1.keystore \
                -storepass $PASS \
                -noprompt
        fi
    done
done

# Clean up certificates in current directory (but keep them in the certificates directory)
rm *.cer

echo "Keystores and certificates created successfully!" 