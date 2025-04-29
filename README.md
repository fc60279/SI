# myCiencias - Sistema de Armazenamento Seguro de Documentos

Este projeto implementa um sistema seguro de armazenamento de documentos, onde um servidor central armazena ficheiros referentes a declarações, certificados e certidões dos alunos.

## Requisitos

- Java 17 ou superior
- keytool (incluído no JDK)

## Configuração

1. Compile os arquivos Java:
```bash
javac *.java
```

2. Execute o script para gerar as keystores:

No Windows:
```bash
setup_keystores.bat
create_server_keystore.bat
```

No Linux/Mac:
```bash
chmod +x setup_keystores.sh
./setup_keystores.sh
chmod +x create_server_keystore.sh
./create_server_keystore.sh
```

## Uso do Servidor

Para iniciar o servidor:
```bash
java myCienciasServer <porto>
```
Exemplo:
```bash
java myCienciasServer 23456
```

## Uso do Cliente

O cliente suporta as seguintes operações:

### Criar Novo Utilizador (-n)
```bash
java myCiencias -a <serverAddress> -n <username> <password>
```
Exemplo:
```bash
java myCiencias -a 127.0.0.1:23456 -n novouser minhasenha
```

### 1. Cifrar e Enviar Ficheiros (-c)
```bash
java myCiencias -a <serverAddress> -u <user do emissor> -p <password do user> -k <password da keystore do user> -e <user do estudante> -c <ficheiros>
```
Exemplo:
```bash
java myCiencias -a 127.0.0.1:23456 -u silva -p password123 -k keystore123 -e maria -c declaracaoPasse.pdf declaracaoMatricula.pdf
```

### 2. Assinar e Enviar Ficheiros (-s)
```bash
java myCiencias -a <serverAddress> -u <user do emissor> -p <password do user> -k <password da keystore do user> -e <user do estudante> -s <ficheiros>
```
Exemplo:
```bash
java myCiencias -a 127.0.0.1:23456 -u silva -p password123 -k keystore123 -e maria -s declaracaoPasse.pdf declaracaoMatricula.pdf
```

### 3. Assinar, Cifrar e Enviar Ficheiros (-b)
```bash
java myCiencias -a <serverAddress> -u <user do emissor> -p <password do user> -k <password da keystore do user> -e <user do estudante> -b <ficheiros>
```
Exemplo:
```bash
java myCiencias -a 127.0.0.1:23456 -u silva -p password -k keystore -e maria -b declaracaoPasse.pdf declaracaoMatricula.pdf
```

### 4. Receber e Verificar Ficheiros (-g)
```bash
java myCiencias -a <serverAddress> -e <user do estudante> -p <password do user> -k <password da keystore do user> -g <ficheiros>
```
Exemplo:
```bash
java myCiencias -a 127.0.0.1:23456 -e maria -p password123 -k keystore123 -g declaracaoPasse.pdf declaracaoMatricula.pdf
```

## Estrutura de Ficheiros no Servidor

Os ficheiros são armazenados no servidor na seguinte estrutura:
```
server_files/
└── <user do estudante>/
    ├── <filename>.encrypted
    ├── <filename>.secretKey.<user do estudante>
    ├── <filename>.signed
    ├── <filename>.signature.<user do emissor>
    ├── <filename>.secure
    └── ...
```

## Segurança

- Comunicação Cliente-Servidor: SSL/TLS para autenticidade do servidor e confidencialidade
- Integridade do ficheiro de passwords: MAC (Message Authentication Code)
- Criptografia assimétrica: RSA com chaves de 2048 bits
- Criptografia simétrica: AES com chaves de 128 bits
- Assinaturas digitais: SHA256withRSA
- Keystores: PKCS12

## Comunicação Segura

O sistema implementa comunicação segura usando o protocolo SSL/TLS:

1. Autenticidade do servidor: O servidor possui um certificado que é verificado pelo cliente
2. Confidencialidade: Toda a comunicação é cifrada, protegendo contra escutas
3. Integridade: Os dados transmitidos são protegidos contra alterações

A primeira vez que o cliente se conecta, o certificado do servidor é adicionado ao truststore do cliente.

## Notas

- As keystores são protegidas com a senha padrão "123456"
- Cada utilizador tem o seu próprio par de chaves na keystore
- Os certificados dos destinatários estão nas keystores dos emissores
- Os ficheiros são verificados para unicidade no servidor
- Os utilizadores padrão são: silva, maria, joao, ana 