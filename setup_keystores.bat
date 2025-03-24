@echo off
setlocal

set PASS=123456
set USERS=silva maria joao ana

:: Generate keystores and certificates for each user
for %%u in (%USERS%) do (
    echo Generating keystore for %%u...
    keytool -genkeypair -alias %%u -keyalg RSA -keysize 2048 -dname "CN=%%u" -validity 365 -storetype PKCS12 -keystore %%u.keystore -storepass %PASS% -keypass %PASS%
    
    echo Exporting certificate for %%u...
    keytool -exportcert -alias %%u -file %%u.cer -keystore %%u.keystore -storepass %PASS%
)

:: Import certificates into other users' keystores
for %%u in (%USERS%) do (
    for %%v in (%USERS%) do (
        if not "%%u"=="%%v" (
            echo Importing %%v's certificate into %%u's keystore...
            keytool -importcert -alias %%v -file %%v.cer -keystore %%u.keystore -storepass %PASS% -noprompt
        )
    )
)

:: Clean up certificate files
for %%u in (%USERS%) do (
    del %%u.cer
)

echo.
echo Keystores created successfully!
echo. 