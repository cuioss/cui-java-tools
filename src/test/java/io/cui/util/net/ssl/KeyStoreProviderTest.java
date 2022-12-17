package io.cui.util.net.ssl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import io.cui.util.support.Generators;

class KeyStoreProviderTest {

    /**
     * Test RSA-2048
     *
     * @throws Exception
     */
    @Test
    void testRsaCertificate() throws Exception {

        X509Certificate x509Certificate = createX509Certificate("RSA", 2048, "SHA256WithRSAEncryption");

        KeyMaterialHolder keyHolder = KeyMaterialHolder.builder().keyAlias("RSA2048")
                .keyAlgorithm(KeyAlgorithm.RSA_2048).keyMaterial(x509Certificate.getEncoded()).build();

        Optional<KeyStore> ky =
            KeyStoreProvider.builder().keyStoreType(KeyStoreType.TRUST_STORE).storePassword("StorePassword")
                    .key(keyHolder).build().resolveKeyStore();
        assertTrue(ky.isPresent());

        PublicKey publicKey = ky.get().getCertificate("RSA2048").getPublicKey();

        // CheckIfKey extracted and key created at beginning are the same
        assertEquals(publicKey, x509Certificate.getPublicKey());
    }

    /**
     * Test DSA
     *
     * @throws Exception
     */
    @Test
    void testCertificate() throws Exception {

        X509Certificate x509Certificate = createX509Certificate("DSA", 1024, "SHA224withDSA");

        KeyMaterialHolder keyHolder = KeyMaterialHolder.builder().keyAlias("DSA")
                .keyAlgorithm(KeyAlgorithm.OTHER).keyMaterial(x509Certificate.getEncoded()).build();

        Optional<KeyStore> ky = KeyStoreProvider.builder()
                .keyStoreType(KeyStoreType.TRUST_STORE)
                .storePassword("StorePassword")
                .key(keyHolder)
                .build().resolveKeyStore();
        assertTrue(ky.isPresent());

        PublicKey publicKey = ky.get().getCertificate("DSA").getPublicKey();

        // CheckIfKey extracted and key created at beginning are the same
        assertEquals(publicKey, x509Certificate.getPublicKey());
    }

    @Test
    void testEcCertificate() throws Exception {

        X509Certificate x509Certificate = createX509Certificate("EC", 256, "SHA256withECDSA");

        KeyMaterialHolder keyHolder = KeyMaterialHolder.builder().keyAlias("EC256")
                .keyAlgorithm(KeyAlgorithm.ECDSA_P_256).keyMaterial(x509Certificate.getEncoded()).build();

        Optional<KeyStore> ky =
            KeyStoreProvider.builder().keyStoreType(KeyStoreType.TRUST_STORE).storePassword("StorePassword")
                    .key(keyHolder).build().resolveKeyStore();
        assertTrue(ky.isPresent());

        PublicKey publicKey = ky.get().getCertificate("EC256").getPublicKey();

        // CheckIfKey extracted and key created at beginning are the same
        assertEquals(publicKey, x509Certificate.getPublicKey());
    }

    @Test
    void testKeyStoreCreation() throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        keyStore.store(os, ("pass").toCharArray());

        KeyMaterialHolder keyHolder =
            KeyMaterialHolder.builder().keyAlias("KeyStore").keyAlgorithm(KeyAlgorithm.RSA_2048)
                    .keyHolderType(KeyHolderType.KEY_STORE).keyMaterial(os.toByteArray()).build();

        Optional<KeyStore> ky =
            KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE).storePassword("pass").key(keyHolder)
                    .build().resolveKeyStore();

        // check keyStore was created
        assertTrue(ky.isPresent());
        // check no entries in KeyStore
        assertTrue(ky.get().size() < 1);
    }

    @Test
    void shouldFailOnMultipleKeyStores() throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        keyStore.store(os, ("pass").toCharArray());

        KeyMaterialHolder keyHolder =
            KeyMaterialHolder.builder().keyAlias("KeyStore").keyAlgorithm(KeyAlgorithm.RSA_2048)
                    .keyHolderType(KeyHolderType.KEY_STORE).keyMaterial(os.toByteArray()).build();

        KeyStoreProvider ky = KeyStoreProvider.builder()
                .keyStoreType(KeyStoreType.KEY_STORE)
                .storePassword("pass")
                .key(keyHolder)
                .key(keyHolder)
                .build();

        assertThrows(IllegalStateException.class, () -> {
            ky.resolveKeyStore();
        });
    }

    @Test
    void shouldFailOnemptyKeyStores() throws Exception {
        KeyMaterialHolder keyHolder =
            KeyMaterialHolder.builder().keyAlias("KeyStore").keyAlgorithm(KeyAlgorithm.RSA_2048)
                    .keyHolderType(KeyHolderType.KEY_STORE).keyMaterial(new byte[1]).build();

        KeyStoreProvider ky =
            KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE).storePassword("pass").key(keyHolder)
                    .build();

        assertThrows(IllegalStateException.class, () -> {
            ky.resolveKeyStore();
        });
    }

    @Test
    void testMultipleCerts() throws Exception {

        Collection<KeyMaterialHolder> keyMaterialHolderCollection = new ArrayList<>();

        X509Certificate x509Certificate = createX509Certificate("EC", 256, "SHA256withECDSA");
        KeyMaterialHolder keyHolder = KeyMaterialHolder.builder().keyAlias("EC256")
                .keyAlgorithm(KeyAlgorithm.ECDSA_P_256).keyMaterial(x509Certificate.getEncoded()).build();
        keyMaterialHolderCollection.add(keyHolder);

        keyHolder = KeyMaterialHolder.builder().keyAlias("test2").keyAlgorithm(KeyAlgorithm.ECDSA_P_256)
                .keyMaterial(x509Certificate.getEncoded()).build();
        keyMaterialHolderCollection.add(keyHolder);

        Optional<KeyStore> ky =
            KeyStoreProvider.builder().storePassword("StorePassword").keyStoreType(KeyStoreType.TRUST_STORE)
                    .keys(keyMaterialHolderCollection).build().resolveKeyStore();
        assertTrue(ky.isPresent());

        ky.get().getKey("EC256", keyHolder.getKeyPasswordAsCharArray());

        PublicKey publicKey = ky.get().getCertificate("EC256").getPublicKey();

        assertFalse(ky.get().containsAlias("test"));

        // CheckIfKey extracted and key created at beginning are the same
        assertEquals(publicKey, x509Certificate.getPublicKey());
    }

    /**
     * Generates a X509Certificate.
     *
     * @param algorithm used for the creation of the KeyPair
     * @param keysize of the key
     * @param signatureAlgorithm that was used to create the ContentSigner
     * @return a currently valid X509Certificate
     * @throws Exception on any error
     */
    private X509Certificate createX509Certificate(String algorithm, int keysize, String signatureAlgorithm)
        throws Exception {

        // Set start and end date of certificate
        Date startValid = new Date(System.currentTimeMillis() - 24 * 60 * 1000);
        Date endValid = new Date(System.currentTimeMillis() + 24 * 60 * 1000);

        // Generate public/private KeyPair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keysize, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        X500Name issuer = new X500Name("CN=Ca");

        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        X509v1CertificateBuilder x509Builder =
            new X509v1CertificateBuilder(issuer, serial, startValid, endValid, issuer, subPubKeyInfo);

        ContentSigner signer =
            new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(x509Builder.build(signer));

        return x509Certificate;
    }

    @Test
    void shouldCreateEmptyMinimal() {
        assertFalse(KeyStoreProvider.builder().keyStoreType(KeyStoreType.TRUST_STORE).build().resolveKeyStore()
                .isPresent());
    }

    @Test
    void shouldFailOnInvalidFile() {
        KeyStoreProvider provider =
            KeyStoreProvider.builder().keyStoreType(KeyStoreType.TRUST_STORE).location(new File("notThere")).build();
        assertThrows(IllegalStateException.class, () -> provider.resolveKeyStore());
    }

    @Test
    void shouldHandlEmptyPasswordAsCharArray() {
        KeyStoreProvider provider =
            KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE).build();

        assertNull(provider.getKeyPassword());
        assertNull(provider.getStorePassword());

        assertNotNull(provider.getKeyPasswordAsCharArray());
        assertNotNull(provider.getStorePasswordAsCharArray());

        assertEquals(0, provider.getKeyPasswordAsCharArray().length);
        assertEquals(0, provider.getStorePasswordAsCharArray().length);

    }

    @Test
    void shouldHandleKeyPasswordAsCharArray() {

        String generatedKeyPassword = Generators.randomString();
        KeyStoreProvider provider =
            KeyStoreProvider.builder().keyPassword(generatedKeyPassword).keyStoreType(KeyStoreType.KEY_STORE).build();

        assertEquals(generatedKeyPassword, provider.getKeyPassword());
        assertNull(provider.getStorePassword());

        assertNotNull(provider.getKeyPasswordAsCharArray());
        assertNotNull(provider.getStorePasswordAsCharArray());

        assertEquals(generatedKeyPassword.length(), provider.getKeyPasswordAsCharArray().length);
        assertEquals(0, provider.getStorePasswordAsCharArray().length);
    }

    @Test
    void shouldHandleStorePasswordAsCharArray() {

        String generatedStorePassword = Generators.randomString();
        KeyStoreProvider provider =
            KeyStoreProvider.builder().storePassword(generatedStorePassword).keyStoreType(KeyStoreType.KEY_STORE)
                    .build();

        assertEquals(generatedStorePassword, provider.getStorePassword());
        assertNull(provider.getKeyPassword());

        assertNotNull(provider.getStorePasswordAsCharArray());
        assertNotNull(provider.getKeyPasswordAsCharArray());

        assertEquals(generatedStorePassword.length(), provider.getStorePasswordAsCharArray().length);
        assertEquals(0, provider.getKeyPasswordAsCharArray().length);
    }

    @Test
    void shouldHandleMaterialHolder() {
        KeyStoreProvider provider = KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE).build();
        assertNotNull(provider.getKeys());
        assertTrue(provider.getKeys().isEmpty());

        provider = KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE)
                .key(KeyMaterialHolder.builder().keyMaterial(Generators.generateTestData(100)).build()).build();
        assertEquals(1, provider.getKeys().size());
    }

    // File Based Keystore tests
    @Test
    void shouldHandleEmptyKeyStore() throws KeyStoreException {
        KeyStoreProvider provider =
            KeyStoreProvider.builder().location(KeystoreInformation.EMPTY_KEY_STORE.toFile())
                    .storePassword(KeystoreInformation.PASSWORD).keyStoreType(KeyStoreType.KEY_STORE).build();
        Optional<KeyStore> keystore = provider.resolveKeyStore();
        assertTrue(keystore.isPresent());
        assertEquals(0, keystore.get().size());
    }

    @Test
    void shouldFailEmptyKeyStoreWithoutPassword() {
        KeyStoreProvider provider =
            KeyStoreProvider.builder().location(KeystoreInformation.EMPTY_KEY_STORE.toFile())
                    .keyStoreType(KeyStoreType.KEY_STORE).build();
        assertThrows(IllegalStateException.class, () -> provider.resolveKeyStore());
    }

    @Test
    void shouldHandleUnprotectedEmptyKeyStore() throws KeyStoreException {
        KeyStoreProvider provider =
            KeyStoreProvider.builder().location(KeystoreInformation.EMPTY_KEY_STORE_NO_PASSWORD.toFile())
                    .keyStoreType(KeyStoreType.KEY_STORE).build();
        Optional<KeyStore> keystore = provider.resolveKeyStore();
        assertTrue(keystore.isPresent());
        assertEquals(0, keystore.get().size());
    }

    @Test
    void shouldFailUnprotectedKeyStore() {
        KeyStoreProvider provider =
            KeyStoreProvider.builder().location(KeystoreInformation.EMPTY_KEY_STORE_NO_PASSWORD.toFile())
                    .storePassword(KeystoreInformation.PASSWORD)
                    .keyStoreType(KeyStoreType.KEY_STORE).build();
        assertThrows(IllegalStateException.class, () -> provider.resolveKeyStore());
    }

    @Test
    void shouldHandleSingleEntryKeyStore() throws KeyStoreException, Exception, NoSuchAlgorithmException {
        KeyStoreProvider provider =
            KeyStoreProvider.builder().location(KeystoreInformation.SINGLE_KEY_STORE.toFile())
                    .storePassword(KeystoreInformation.PASSWORD).keyStoreType(KeyStoreType.KEY_STORE).build();
        Optional<KeyStore> keystore = provider.resolveKeyStore();
        assertTrue(keystore.isPresent());
        assertEquals(1, keystore.get().size());
        Key key = keystore.get().getKey(KeystoreInformation.SINGLE_KEY_NAME, provider.getStorePasswordAsCharArray());
        assertNotNull(key);
    }
}
