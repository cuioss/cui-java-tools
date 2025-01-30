/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.net.ssl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.cuioss.tools.support.Generators;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

class KeyStoreProviderTest {

    /**
     * Test RSA-2048
     */
    @Test
    void rsaCertificate() throws Exception {

        var x509Certificate = createX509Certificate("RSA", 2048, "SHA256WithRSAEncryption");

        var keyHolder = KeyMaterialHolder.builder().keyAlias("RSA2048").keyAlgorithm(KeyAlgorithm.RSA_2048)
                .keyMaterial(x509Certificate.getEncoded()).build();

        var ky = KeyStoreProvider.builder().keyStoreType(KeyStoreType.TRUST_STORE).storePassword("StorePassword")
                .key(keyHolder).build().resolveKeyStore();
        assertTrue(ky.isPresent());

        var publicKey = ky.get().getCertificate("RSA2048").getPublicKey();

        // CheckIfKey extracted and key created at beginning are the same
        assertEquals(publicKey, x509Certificate.getPublicKey());
    }

    /**
     * Test DSA
     */
    @Test
    void certificate() throws Exception {

        var x509Certificate = createX509Certificate("DSA", 1024, "SHA224withDSA");

        var keyHolder = KeyMaterialHolder.builder().keyAlias("DSA").keyAlgorithm(KeyAlgorithm.OTHER)
                .keyMaterial(x509Certificate.getEncoded()).build();

        var ky = KeyStoreProvider.builder().keyStoreType(KeyStoreType.TRUST_STORE).storePassword("StorePassword")
                .key(keyHolder).build().resolveKeyStore();
        assertTrue(ky.isPresent());

        var publicKey = ky.get().getCertificate("DSA").getPublicKey();

        // CheckIfKey extracted and key created at beginning are the same
        assertEquals(publicKey, x509Certificate.getPublicKey());
    }

    @Test
    void ecCertificate() throws Exception {

        var x509Certificate = createX509Certificate("EC", 256, "SHA256withECDSA");

        var keyHolder = KeyMaterialHolder.builder().keyAlias("EC256").keyAlgorithm(KeyAlgorithm.ECDSA_P_256)
                .keyMaterial(x509Certificate.getEncoded()).build();

        var ky = KeyStoreProvider.builder().keyStoreType(KeyStoreType.TRUST_STORE).storePassword("StorePassword")
                .key(keyHolder).build().resolveKeyStore();
        assertTrue(ky.isPresent());

        var publicKey = ky.get().getCertificate("EC256").getPublicKey();

        // CheckIfKey extracted and key created at beginning are the same
        assertEquals(publicKey, x509Certificate.getPublicKey());
    }

    @Test
    void keyStoreCreation() throws Exception {

        var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        var os = new ByteArrayOutputStream();
        keyStore.store(os, "pass".toCharArray());

        var keyHolder = KeyMaterialHolder.builder().keyAlias("KeyStore").keyAlgorithm(KeyAlgorithm.RSA_2048)
                .keyHolderType(KeyHolderType.KEY_STORE).keyMaterial(os.toByteArray()).build();

        var ky = KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE).storePassword("pass").key(keyHolder)
                .build().resolveKeyStore();

        // check keyStore was created
        assertTrue(ky.isPresent());
        // check no entries in KeyStore
        assertTrue(ky.get().size() < 1);
    }

    @Test
    void shouldFailOnMultipleKeyStores() throws Exception {

        var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        var os = new ByteArrayOutputStream();
        keyStore.store(os, "pass".toCharArray());

        var keyHolder = KeyMaterialHolder.builder().keyAlias("KeyStore").keyAlgorithm(KeyAlgorithm.RSA_2048)
                .keyHolderType(KeyHolderType.KEY_STORE).keyMaterial(os.toByteArray()).build();

        var ky = KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE).storePassword("pass").key(keyHolder)
                .key(keyHolder).build();

        assertThrows(IllegalStateException.class, ky::resolveKeyStore);
    }

    @Test
    void shouldFailOnEmptyKeyStores() {
        var keyHolder = KeyMaterialHolder.builder().keyAlias("KeyStore").keyAlgorithm(KeyAlgorithm.RSA_2048)
                .keyHolderType(KeyHolderType.KEY_STORE).keyMaterial(new byte[1]).build();

        var ky = KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE).storePassword("pass").key(keyHolder)
                .build();

        assertThrows(IllegalStateException.class, ky::resolveKeyStore);
    }

    @Test
    void multipleCerts() throws Exception {

        Collection<KeyMaterialHolder> keyMaterialHolderCollection = new ArrayList<>();

        var x509Certificate = createX509Certificate("EC", 256, "SHA256withECDSA");
        var keyHolder = KeyMaterialHolder.builder().keyAlias("EC256").keyAlgorithm(KeyAlgorithm.ECDSA_P_256)
                .keyMaterial(x509Certificate.getEncoded()).build();
        keyMaterialHolderCollection.add(keyHolder);

        keyHolder = KeyMaterialHolder.builder().keyAlias("test2").keyAlgorithm(KeyAlgorithm.ECDSA_P_256)
                .keyMaterial(x509Certificate.getEncoded()).build();
        keyMaterialHolderCollection.add(keyHolder);

        var ky = KeyStoreProvider.builder().storePassword("StorePassword").keyStoreType(KeyStoreType.TRUST_STORE)
                .keys(keyMaterialHolderCollection).build().resolveKeyStore();
        assertTrue(ky.isPresent());

        ky.get().getKey("EC256", keyHolder.getKeyPasswordAsCharArray());

        var publicKey = ky.get().getCertificate("EC256").getPublicKey();

        assertFalse(ky.get().containsAlias("test"));

        // CheckIfKey extracted and key created at beginning are the same
        assertEquals(publicKey, x509Certificate.getPublicKey());
    }

    /**
     * Generates a X509Certificate.
     *
     * @param algorithm          used for the creation of the KeyPair
     * @param keySize            of the key
     * @param signatureAlgorithm that was used to create the ContentSigner
     * @return a currently valid X509Certificate
     * @throws Exception on any error
     */
    private X509Certificate createX509Certificate(String algorithm, int keySize, String signatureAlgorithm)
            throws Exception {

        // Set start and end date of certificate
        var startValid = new Date(System.currentTimeMillis() - 24 * 60 * 1000);
        var endValid = new Date(System.currentTimeMillis() + 24 * 60 * 1000);

        // Generate public/private KeyPair
        var keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize, new SecureRandom());
        var keyPair = keyPairGenerator.generateKeyPair();

        var serial = BigInteger.valueOf(System.currentTimeMillis());
        var issuer = new X500Name("CN=Ca");

        var subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        var x509Builder = new X509v1CertificateBuilder(issuer, serial, startValid, endValid, issuer, subPubKeyInfo);

        var signer = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(x509Builder.build(signer));
    }

    @Test
    void shouldCreateEmptyMinimal() {
        assertFalse(KeyStoreProvider.builder().keyStoreType(KeyStoreType.TRUST_STORE).build().resolveKeyStore()
                .isPresent());
    }

    @Test
    void shouldFailOnInvalidFile() {
        var provider = KeyStoreProvider.builder().keyStoreType(KeyStoreType.TRUST_STORE).location(new File("notThere"))
                .build();
        assertThrows(IllegalStateException.class, provider::resolveKeyStore);
    }

    @Test
    void shouldHandleEmptyPasswordAsCharArray() {
        var provider = KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE).build();

        assertNull(provider.getKeyPassword());
        assertNull(provider.getStorePassword());

        assertNotNull(provider.getKeyPasswordAsCharArray());
        assertNotNull(provider.getStorePasswordAsCharArray());

        assertEquals(0, provider.getKeyPasswordAsCharArray().length);
        assertEquals(0, provider.getStorePasswordAsCharArray().length);

    }

    @Test
    void shouldHandleKeyPasswordAsCharArray() {

        var generatedKeyPassword = Generators.randomString();
        var provider = KeyStoreProvider.builder().keyPassword(generatedKeyPassword).keyStoreType(KeyStoreType.KEY_STORE)
                .build();

        assertEquals(generatedKeyPassword, provider.getKeyPassword());
        assertNull(provider.getStorePassword());

        assertNotNull(provider.getKeyPasswordAsCharArray());
        assertNotNull(provider.getStorePasswordAsCharArray());

        assertEquals(generatedKeyPassword.length(), provider.getKeyPasswordAsCharArray().length);
        assertEquals(0, provider.getStorePasswordAsCharArray().length);
    }

    @Test
    void shouldHandleStorePasswordAsCharArray() {

        var generatedStorePassword = Generators.randomString();
        var provider = KeyStoreProvider.builder().storePassword(generatedStorePassword)
                .keyStoreType(KeyStoreType.KEY_STORE).build();

        assertEquals(generatedStorePassword, provider.getStorePassword());
        assertNull(provider.getKeyPassword());

        assertNotNull(provider.getStorePasswordAsCharArray());
        assertNotNull(provider.getKeyPasswordAsCharArray());

        assertEquals(generatedStorePassword.length(), provider.getStorePasswordAsCharArray().length);
        assertEquals(0, provider.getKeyPasswordAsCharArray().length);
    }

    @Test
    void shouldHandleMaterialHolder() {
        var provider = KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE).build();
        assertNotNull(provider.getKeys());
        assertTrue(provider.getKeys().isEmpty());

        provider = KeyStoreProvider.builder().keyStoreType(KeyStoreType.KEY_STORE)
                .key(KeyMaterialHolder.builder().keyMaterial(Generators.generateTestData(100)).build()).build();
        assertEquals(1, provider.getKeys().size());
    }

    // File Based Keystore tests
    @Test
    void shouldHandleEmptyKeyStore() throws KeyStoreException {
        var provider = KeyStoreProvider.builder().location(KeystoreInformation.EMPTY_KEY_STORE.toFile())
                .storePassword(KeystoreInformation.PASSWORD).keyStoreType(KeyStoreType.KEY_STORE).build();
        var keystore = provider.resolveKeyStore();
        assertTrue(keystore.isPresent());
        assertEquals(0, keystore.get().size());
    }

    @Test
    void shouldFailEmptyKeyStoreWithoutPassword() {
        var provider = KeyStoreProvider.builder().location(KeystoreInformation.EMPTY_KEY_STORE.toFile())
                .keyStoreType(KeyStoreType.KEY_STORE).build();
        assertThrows(IllegalStateException.class, provider::resolveKeyStore);
    }

    @Test
    void shouldHandleUnprotectedEmptyKeyStore() throws KeyStoreException {
        var provider = KeyStoreProvider.builder().location(KeystoreInformation.EMPTY_KEY_STORE_NO_PASSWORD.toFile())
                .keyStoreType(KeyStoreType.KEY_STORE).build();
        var keystore = provider.resolveKeyStore();
        assertTrue(keystore.isPresent());
        assertEquals(0, keystore.get().size());
    }

    @Test
    void shouldFailUnprotectedKeyStore() {
        var provider = KeyStoreProvider.builder().location(KeystoreInformation.EMPTY_KEY_STORE_NO_PASSWORD.toFile())
                .storePassword(KeystoreInformation.PASSWORD).keyStoreType(KeyStoreType.KEY_STORE).build();
        assertThrows(IllegalStateException.class, provider::resolveKeyStore);
    }

    @Test
    void shouldHandleSingleEntryKeyStore() throws Exception {
        var provider = KeyStoreProvider.builder().location(KeystoreInformation.SINGLE_KEY_STORE.toFile())
                .storePassword(KeystoreInformation.PASSWORD).keyStoreType(KeyStoreType.KEY_STORE).build();
        var keystore = provider.resolveKeyStore();
        assertTrue(keystore.isPresent());
        assertEquals(1, keystore.get().size());
        var key = keystore.get().getKey(KeystoreInformation.SINGLE_KEY_NAME, provider.getStorePasswordAsCharArray());
        assertNotNull(key);
    }
}
