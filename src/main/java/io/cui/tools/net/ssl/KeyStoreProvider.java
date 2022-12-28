package io.cui.tools.net.ssl;

import static io.cui.tools.base.Preconditions.checkState;
import static io.cui.tools.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Optional;

import io.cui.tools.base.BooleanOperations;
import io.cui.tools.io.MorePaths;
import io.cui.tools.logging.CuiLogger;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.Singular;
import lombok.ToString;

/**
 * Provides instances of {@link KeyStore} defined by either given file / storePassword combination
 * or one or more {@link KeyMaterialHolder} containing key-material as a byte-array.
 * <h2>Some words on the String-representation of passwords</h2>
 * <em>No</em> it is not (much) more secure to store them in a char[] because of not being part of
 * the string-pool:
 * <ul>
 * <li>If an attacker is on your machine debugging the string-pool you are doomed anyway.</li>
 * <li>In most frameworks / user-land code there are some places where input / configuration data is
 * represented as String on the way to the more secure "give me a char[]" parts. So it is usually in
 * the String pool anyway.</li>
 * </ul>
 * <p>
 * So: In theory the statements made by the Java Cryptography Architecture guide
 * ("<a href=
 * "http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#PBEEx">...</a>")
 * are correct but in our scenarios they will increase security only a small amount and introduce
 * potential bugs and will therefore be ignored for this keyStoreType.
 * </p>
 * <p>
 * It is more important to avoid accidental printing on logs and such, what is handled by this
 * keyStoreType.
 * </p>
 * Therefore, this class uses String-based handling of credentials, for simplification and provide
 * shortcuts for creating char[], see {@link #getStorePasswordAsCharArray()} and
 * {@link #getKeyPasswordAsCharArray()}
 *
 * @author Oliver Wolff
 * @author Nikola Marijan
 *
 */
@Builder
@EqualsAndHashCode(of = { "keyStoreType", "location" }, doNotUseGetters = true)
@ToString(of = { "keyStoreType", "location" }, doNotUseGetters = true)
public class KeyStoreProvider implements Serializable {

    private static final String UNABLE_TO_CREATE_KEYSTORE = "The creation of a KeyStore did not succeed";
    private static final String UNABLE_TO_CREATE_CERTIFICATE = "The creation of a Certificate-Object did not succeed";

    private static final CuiLogger log = new CuiLogger(KeyStoreProvider.class);

    private static final long serialVersionUID = 496381186621534386L;

    @NonNull
    @Getter
    private final KeyStoreType keyStoreType;

    @Getter
    // We can not use Path here, because it is not Serializable
    private final File location;

    /** The password for the keystore aka the storage. */
    @Getter
    private final String storePassword;

    /**
     * (Optional) password for the keystore-key. Due to its nature this is usually only necessary
     * for {@link KeyStoreType#KEY_STORE}
     */
    @Getter
    private final String keyPassword;

    @Getter
    @Singular
    private final Collection<KeyMaterialHolder> keys;

    /**
     * Instantiates a {@link KeyStore} according to the given parameter. In case of
     * {@link #getKeys()} and {@link #getLocation()} being present the {@link KeyStore} will
     * <em>only</em> be created from the {@link #getKeys()}. The file will be ignored.
     *
     * @return an {@link Optional} on a {@link KeyStore} created from the configured parameter. In
     *         case of {@link #getKeys} and {@link #getLocation()} being {@code null} / empty it
     *         will return {@link Optional#empty()}
     * @throws IllegalStateException in case the location-file is not null but not readable or of
     *             the key-store creation did fail.
     */
    public Optional<KeyStore> resolveKeyStore() {
        if (BooleanOperations.areAllTrue(keys.isEmpty(), null == location)) {
            log.debug("Neither file nor keyMaterial provided, returning Optional#empty");
            return Optional.empty();
        }
        if (null != location) {
            log.debug("Checking whether configured {} path is readable", location.getAbsolutePath());
            checkState(MorePaths.checkReadablePath(location.toPath(), false, true),
                    "'%s' is not readable check logs for reason", location.getAbsolutePath());
        }
        if (!keys.isEmpty()) {
            return retrieveFromKeys();
        }
        return retrieveFromFile();
    }

    private Optional<KeyStore> retrieveFromFile() {
        log.debug("Retrieving java.security.KeyStore from configured file '{}'", location);
        try (InputStream input = new BufferedInputStream(new FileInputStream(location))) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(input, getStorePasswordAsCharArray());
            return Optional.of(keyStore);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IllegalStateException(UNABLE_TO_CREATE_KEYSTORE, e);
        }
    }

    private Optional<KeyStore> retrieveFromKeys() {
        log.debug("Retrieving java.security.KeyStore from configured keys");
        KeyStore keyStore = createEmptyKeyStore();
        for (KeyMaterialHolder key : keys) {
            log.debug("Adding Key {}", key);
            requireNonNull(key);
            switch (key.getKeyHolderType()) {
                case SINGLE_KEY:
                    // adds single certificate to the keyStore
                    addCertificateToKeyStore(key, keyStore);
                    break;
                case KEY_STORE:
                    checkState(keys.size() == 1, "It is not allowed that there are multiple KeyStores");
                    keyStore = createKeyStoreFromByteArray(key);
                    break;
                default:
                    throw new UnsupportedOperationException("KeyHolderType is not defined: " + key.getKeyHolderType());
            }
        }
        return Optional.of(keyStore);
    }

    private static void addCertificateToKeyStore(KeyMaterialHolder key, KeyStore keyStore) {
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException("Unable to instantiate CertificateFactory", e);
        }

        try (InputStream certStream = new ByteArrayInputStream(key.getKeyMaterial())) {
            Certificate cert = cf.generateCertificate(certStream);
            keyStore.setCertificateEntry(key.getKeyAlias(), cert);
        } catch (KeyStoreException | CertificateException | IOException e) {
            throw new IllegalStateException(UNABLE_TO_CREATE_CERTIFICATE, e);
        }
    }

    private KeyStore createKeyStoreFromByteArray(KeyMaterialHolder key) {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Unable to instantiate KeyStore", e);
        }
        try (InputStream keyStoreStream = new ByteArrayInputStream(key.getKeyMaterial())) {
            keyStore.load(keyStoreStream, getStorePasswordAsCharArray());
            return keyStore;
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IllegalStateException(UNABLE_TO_CREATE_KEYSTORE, e);
        }
    }

    private KeyStore createEmptyKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, getStorePasswordAsCharArray());
            return keyStore;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IllegalStateException(UNABLE_TO_CREATE_KEYSTORE, e);
        }
    }

    /**
     * @return NPE-safe char-array representation of {@link #getStorePassword()}. If storePassword
     *         is {@code null} or empty it returns an empty char[], never {@code null}
     */
    public char[] getStorePasswordAsCharArray() {
        return toCharArray(storePassword);
    }

    /**
     * @return NPE-safe char-array representation of {@link #getKeyPassword()}. If keyPassword is
     *         {@code null} or empty it returns an empty char[], never {@code null}
     */
    public char[] getKeyPasswordAsCharArray() {
        return toCharArray(keyPassword);
    }

    /**
     * In case of accessing data on the {@link KeyStore} sometimes it is needed to access the
     * defined key-password. If not present the api needs the store-password instead. This is method
     * is a convenience method for dealing with that case.
     *
     * @return the keyPassword, if set or the store-password otherwise
     */
    public char[] getKeyOrStorePassword() {
        if (isEmpty(keyPassword)) {
            return getStorePasswordAsCharArray();
        }
        return getKeyPasswordAsCharArray();
    }

    /**
     * @param password to be converted. May be {@code null} or empty
     * @return NPE-safe char-array representation of given password. If password is
     *         {@code null} or empty it returns an empty char[], never {@code null}
     */
    static final char[] toCharArray(String password) {
        if (isEmpty(password)) {
            return new char[0];
        }
        return password.toCharArray();
    }
}
