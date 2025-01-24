import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.security.KeyPair;

import org.example.*;



public class JwtGeneratorTest {
    @Test
    public void testloadKeyPairValidPath() throws Exception {

        // Replace with valid paths to test with real keys
        String privateKeyPath ="../rsakeypair/private_key.pem";
        String publicKeyPath ="../rsakeypair/public_key.pem";

        // Simulate behavior for testing
        assertDoesNotThrow( () -> {
            KeyPair keyPair = JwtGenerator.loadKeyPair(privateKeyPath, publicKeyPath);

            // Assert that a valid KeyPair is returned
            assertNotNull(keyPair, "KeyPair should not be null");
            assertNotNull(keyPair.getPrivate(),"Private key should not be null");
            assertNotNull(keyPair.getPublic(), "Public key should not be null");
        });



    }

    @Test
    public void testloadKeyPairInvalidPath() {
        // Replace with valid paths to test with real keys
        String privateKeyPath ="../invalid/private_key.pem";
        String publicKeyPath ="../invalid/public_key.pem";

        Exception exception =assertThrows(Exception.class, () ->
                JwtGenerator.loadKeyPair(privateKeyPath, publicKeyPath)
        );
    }
    @Test
    public void testgenerateJwt() {


    }
}
