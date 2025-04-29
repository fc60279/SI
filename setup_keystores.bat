@echo off
setlocal

rem Password for all keystores
set PASS=123456

rem Create certificates directory if it doesn't exist
if not exist ..\certificates mkdir ..\certificates

rem Create keystores for test users
for %%u in (silva maria joao ana) do (
    rem Generate key pair
    keytool -genkeypair ^
        -alias %%u ^
        -keyalg RSA ^
        -keysize 2048 ^
        -dname "CN=%%u" ^
        -validity 365 ^
        -storetype PKCS12 ^
        -keystore %%u.keystore ^
        -storepass %PASS% ^
        -keypass %PASS%

    rem Export certificate
    keytool -exportcert ^
        -alias %%u ^
        -file %%u.cer ^
        -keystore %%u.keystore ^
        -storepass %PASS%
        
    rem Copy certificate to the certificates directory
    copy %%u.cer ..\certificates\
)

rem Import certificates into each keystore
for %%u1 in (silva maria joao ana) do (
    for %%u2 in (silva maria joao ana) do (
        if not "%%u1"=="%%u2" (
            keytool -importcert ^
                -alias %%u2 ^
                -file %%u2.cer ^
                -keystore %%u1.keystore ^
                -storepass %PASS% ^
                -noprompt
        )
    )
)

rem Clean up certificates in current directory (but keep them in the certificates directory)
del *.cer

echo Keystores and certificates created successfully!
endlocal 