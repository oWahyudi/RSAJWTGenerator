package org.example;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JwtGenerator {

    public static KeyPair loadKeyPair(String privateKeyPath, String publicKeyPath) throws Exception {

        final String BEGIN_PRIVATE_KEY ="-----BEGIN PRIVATE KEY-----";
        final String END_PRIVATE_KEY ="-----END PRIVATE KEY-----";
        final String BEGIN_PUBLIC_KEY ="-----BEGIN PUBLIC KEY-----";
        final String END_PUBLIC_KEY ="-----END PUBLIC KEY-----";
        final String ALGORITHM ="RSA";

        //Load Private Key
        byte[] privateKeyBytes= Files.readAllBytes(Paths.get(privateKeyPath));
        String privateKeyPEM= new String(privateKeyBytes)
                .replace(BEGIN_PRIVATE_KEY,"")
                .replace(END_PRIVATE_KEY,"")
                .replaceAll("\\s","");

        byte[] decodedPrivateKey= Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec privateKeySpec=new PKCS8EncodedKeySpec(decodedPrivateKey);
        PrivateKey privateKey= KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec);

        //Load Public Key
        byte[] publicKeyBytes= Files.readAllBytes(Paths.get(publicKeyPath));
        String publicKeyPEM=new String(publicKeyBytes)
                .replace(BEGIN_PUBLIC_KEY,"")
                .replace(END_PUBLIC_KEY,"")
                .replaceAll("\\s","");
        byte[] decodedPublicKey=Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec publicKeySpec=new X509EncodedKeySpec(decodedPublicKey);
        PublicKey publicKey=KeyFactory.getInstance(ALGORITHM).generatePublic(publicKeySpec);

        return new KeyPair(publicKey,privateKey);
    }

    public static String generateJWT(KeyPair keyPair) {
        return "";
    }
}
