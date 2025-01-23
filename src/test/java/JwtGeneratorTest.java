import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import java.security.KeyPair;

import org.example.*;



public class JwtGeneratorTest {
    @Test
    public void testLoadKeyPairValidPath() throws Exception {

        // Replace with valid paths to test with real keys
        String privateKeyPath ="private_key.pem";
        String publicKeyPath ="public_key.pem";

        // Simulate behavior for testing
        KeyPair keyPair = JwtGenerator.LoadKeyPair(privateKeyPath, publicKeyPath);

        // Assert that a valid KeyPair is returned
        assertNotNull(keyPair, "KeyPair should not be null");
    }
    @Test
    public void testGenerateJwt() {


    }
}
