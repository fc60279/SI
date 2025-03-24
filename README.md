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
```

No Linux/Mac:
```bash
chmod +x setup_keystores.sh
./setup_keystores.sh
------------------------------
sh setup_keystores.sh
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

O cliente suporta quatro operações principais:

### 1. Cifrar e Enviar Ficheiros (-c)
```bash
java myCiencias -a <serverAddress> -u <user do emissor> -e <user do estudante> -c <ficheiros>
```
Exemplo:
```bash
java myCiencias -a 127.0.0.1:23456 -u silva -e maria -c declaracaoPasse.pdf declaracaoMatricula.pdf
```

### 2. Assinar e Enviar Ficheiros (-s)
```bash
java myCiencias -a <serverAddress> -u <user do emissor> -e <user do estudante> -s <ficheiros>
```
Exemplo:
```bash
java myCiencias -a 127.0.0.1:23456 -u silva -e maria -s declaracaoPasse.pdf declaracaoMatricula.pdf
```

### 3. Assinar, Cifrar e Enviar Ficheiros (-b)
```bash
java myCiencias -a <serverAddress> -u <user do emissor> -e <user do estudante> -b <ficheiros>
```
Exemplo:
```bash
java myCiencias -a 127.0.0.1:23456 -u silva -e maria -b declaracaoPasse.pdf declaracaoMatricula.pdf
```

### 4. Receber e Verificar Ficheiros (-g)
```bash
java myCiencias -a <serverAddress> -e <user do estudante> -g <ficheiros>
```
Exemplo:
```bash
java myCiencias -a 127.0.0.1:23456 -e maria -g declaracaoPasse.pdf declaracaoMatricula.pdf
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

- Criptografia assimétrica: RSA com chaves de 2048 bits
- Criptografia simétrica: AES com chaves de 128 bits
- Assinaturas digitais: SHA256withRSA
- Keystores: PKCS12

## Notas

- As keystores são protegidas com a senha padrão "123456"
- Cada utilizador tem o seu próprio par de chaves na keystore
- Os certificados dos destinatários estão nas keystores dos emissores
- Os ficheiros são verificados para unicidade no servidor
- Os utilizadores padrão são: silva, maria, joao, ana 