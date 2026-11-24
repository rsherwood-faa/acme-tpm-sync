package gov.dot.faa.ang.idms.acmetpm.crypto.bridge;

import module java.base;
import java.security.cert.X509Certificate; // This is imported through the module, but the code linter is confused.
import java.security.*;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.*;

import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.WINDOWS)
public class CapiTpmBridgeTest {
    private final String testAlias = "test-tpm-key-" + UUID.randomUUID();
    private final String testContainer = "TestTpmContainer-" + UUID.randomUUID();
    private final String testSubjectDN = "CN=JUnitTpmTest";

    @AfterEach 
    void cleanupKeyStoreEntry() {
        try {
            KeyStore ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            ks.load(null, null);
            if (ks.containsAlias(testAlias)) {
                // Remove the testAlias key and store
                ks.deleteEntry(testAlias);
                ks.store(null, null);
            }
        } catch (Exception e) {
            System.err.println("Unable to clean up key with alias " + testAlias);
        }
    }

    @Test
    void shouldGenerateNonExportableTpmKeyAndSignPayload() throws Throwable {
        // Generate a TPM key using the CapiTpmBridge
        assertDoesNotThrow(() -> CapiTpmBridge.generateTpmKey(testAlias, testContainer, testSubjectDN), "CapiTpmBridge.generateTpmKey should not throw an exception");

        // Check for errors returned by the native function (if any)
        

        // Verify that the keystore contains the expected entry
        KeyStore ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
        ks.load(null, null);
        assertTrue(ks.containsAlias(testAlias), "Generated key alias should exist in the keystore.");

        // Verify the certificate DN
        X509Certificate cert = assertInstanceOf(X509Certificate.class, ks.getCertificate(testAlias));
        assertEquals(testSubjectDN, cert.getSubjectX500Principal().getName());

        // Verify the key
        RSAPublicKey publicKey = assertInstanceOf(RSAPublicKey.class, cert.getPublicKey());
        assertEquals(2048, publicKey.getModulus().bitLength());

        // Verify that key is opaque and non-exportable
        PrivateKey privateKey = (PrivateKey) ks.getKey(testAlias, null);
        assertNotNull(privateKey, "Private Key should not be null");
        assertNull(privateKey.getEncoded(), "Attempting to get the bits of the private key should fail");

        // Test signature and verification
        var payload = "tpm-hardware-test-message".getBytes(StandardCharsets.UTF_8);

        Signature signature = Signature.getInstance("SHA256withRSA", "SunMSCAPI");
        signature.initSign(privateKey);
        signature.update(payload);
        var signatureBytes = signature.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(payload);
        assertTrue(verifier.verify(signatureBytes), "Signature produced by TPM private key must be verifiable with corresponding public key.");

    }

}
