package org.example;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

public class JwtGenerator {

    /**
     * Loads an RSA KeyPair from the specified private and public key files.
     * <p>
     * This method reads the provided private and public key files in PEM format,
     * decodes them from Base64, and generates a corresponding KeyPair object.
     *
     * @param privateKeyPath The path to the private key file in PEM format.
     * @param publicKeyPath  The path to the public key file in PEM format.
     * @return A KeyPair object containing the RSA public and private keys.
     * @throws Exception If an error occurs while reading or decoding the keys.
     */
    public static KeyPair loadKeyPair(String privateKeyPath, String publicKeyPath) throws Exception {
        // Constants for PEM format header and footers
        final String BEGIN_PRIVATE_KEY ="-----BEGIN PRIVATE KEY-----";
        final String END_PRIVATE_KEY ="-----END PRIVATE KEY-----";
        final String BEGIN_PUBLIC_KEY ="-----BEGIN PUBLIC KEY-----";
        final String END_PUBLIC_KEY ="-----END PUBLIC KEY-----";

        // Algorithm used for key generation
        final String ALGORITHM ="RSA";

        // Load Private Key
        // Read the private key file content as byte array
        byte[] privateKeyBytes= Files.readAllBytes(Paths.get(privateKeyPath));

        // Convert the private key content to a string and remove PEM headers, footers, and whitespace
        String privateKeyPEM= new String(privateKeyBytes)
                .replace(BEGIN_PRIVATE_KEY,"")
                .replace(END_PRIVATE_KEY,"")
                .replaceAll("\\s","");

        // Decode the Base64-encoded private key to a byte array
        byte[] decodedPrivateKey= Base64.getDecoder().decode(privateKeyPEM);
        // Create a PKCS8EncodedKeySpec from decoded byte array
        // Private Key is using PKCS8 format
        PKCS8EncodedKeySpec privateKeySpec=new PKCS8EncodedKeySpec(decodedPrivateKey);

        // Generate the private key object from the key specification
        PrivateKey privateKey= KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec);

        // Load Public Key
        // Read the public key file content as a byte array
        byte[] publicKeyBytes= Files.readAllBytes(Paths.get(publicKeyPath));

        // Convert the public key content to as string and remove PEM headers, footers, and whitespace
        String publicKeyPEM=new String(publicKeyBytes)
                .replace(BEGIN_PUBLIC_KEY,"")
                .replace(END_PUBLIC_KEY,"")
                .replaceAll("\\s","");

        // Decode the Base64-encoded public key to a byte array
        byte[] decodedPublicKey=Base64.getDecoder().decode(publicKeyPEM);

        // Create an X509EncodedKeySpec from the decoded byte array
        // Public Key is using X509 Format
        X509EncodedKeySpec publicKeySpec=new X509EncodedKeySpec(decodedPublicKey);

        // Generate  the public key object from the key specification
        PublicKey publicKey=KeyFactory.getInstance(ALGORITHM).generatePublic(publicKeySpec);

        // Return the KeyPair containing both the private and public keys
        return new KeyPair(publicKey,privateKey);
    }

    /**
     * Generates a JWT using the provided RSA key pair.
     *
     * @param keyPair The RSA key pair containing the private and public keys.
     * @return A signed JWT as a string.
     */
    public static String generateJWT(KeyPair keyPair) {
        //Define header parameters
        Map<String,Object> headerMap=Map.of(
                "alg","RS256", //Algorithm
                "typ","JWT" //Token type
        );

        return Jwts.builder()
                .header()
                .add(headerMap)
                .and()
                .claim("publicKey", encodePublicKey(keyPair))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    /**
     * Encodes the public key as a Base64 string.
     *
     * @param keyPair The RSA key pair.
     * @return The Base64-encoded public key.
     */
    private static String encodePublicKey(KeyPair keyPair) {
        return Encoders.BASE64.encode(keyPair.getPublic().getEncoded());
    }

}
