@echo off
setlocal

rem Password for server keystore
set PASS=123456

rem Create server keystore directory if it doesn't exist
if not exist ..\ssl mkdir ..\ssl

rem Generate server keypair and self-signed certificate
keytool -genkeypair ^
    -alias myCienciasServer ^
    -keyalg RSA ^
    -keysize 2048 ^
    -validity 365 ^
    -keystore server.keystore ^
    -storepass %PASS% ^
    -keypass %PASS% ^
    -dname "CN=myCienciasServer,OU=Departamento de Informatica,O=Faculdade de Ciencias,C=PT"

rem Export server certificate
keytool -exportcert ^
    -alias myCienciasServer ^
    -file server.cer ^
    -keystore server.keystore ^
    -storepass %PASS%

rem Create truststore for clients
keytool -importcert ^
    -alias myCienciasServer ^
    -file server.cer ^
    -keystore truststore.jks ^
    -storepass %PASS% ^
    -noprompt

rem Copy keystores to ssl directory
copy server.keystore ..\ssl\
copy truststore.jks ..\ssl\

echo Server keystore and truststore created successfully!
endlocal 