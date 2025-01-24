# RSAJWTGenerator
The RSAJWTGenerator is a utility for creating and signing JSON Web Tokens (JWTs) using RSA key pairs. It leverages the RSA public-key cryptosystem to provide secure, tamper-proof tokens for use in authentication, authorization, and secure data exchange.

# Generating RSA Public and Private Keys with OpenSSL

To create RSA public and private keys using OpenSSL, follow these steps:

## Step 1: Generate the RSA Private Key

Run the following command to generate a 2048-bit RSA private key:

```bash
openssl genpkey -algorithm RSA -out private_key.pem

```

## Step 2: Extract the Public Key from the Private Key
```bash
openssl rsa -pubout -in private_key.pem -out public_key.pem

```