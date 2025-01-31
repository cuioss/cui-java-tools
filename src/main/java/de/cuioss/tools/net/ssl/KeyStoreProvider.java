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

import de.cuioss.tools.base.BooleanOperations;
import de.cuioss.tools.io.MorePaths;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.Singular;
import lombok.ToString;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Optional;

import static de.cuioss.tools.base.Preconditions.checkState;
import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

/**
 * Provides access to a {@link KeyStore}. The store can be loaded from a file or
 * created from a list of {@link KeyMaterialHolder}s. The provider ensures proper
 * handling of passwords and key materials.
 * <p>
 * If both a file location and key materials are provided, the store will be
 * created only from the key materials. The file location will be ignored.
 * </p>
 * <p>
 * When using a file location, ensure that:
 * </p>
 * <ul>
 *   <li>The file exists and is readable</li>
 *   <li>The store password is correct</li>
 *   <li>The file contains a valid keystore</li>
 * </ul>
 * 
 * @author Oliver Wolff
 * @author Nikola Marijan
 *
 */
@Builder
@EqualsAndHashCode(of = {"keyStoreType", "location"}, doNotUseGetters = true)
@ToString(of = {"keyStoreType", "location"}, doNotUseGetters = true)
public class KeyStoreProvider implements Serializable {

    private static final String UNABLE_TO_CREATE_KEYSTORE = "The creation of a KeyStore did not succeed";
    private static final String UNABLE_TO_CREATE_CERTIFICATE = "The creation of a Certificate-Object did not succeed";

    private static final CuiLogger LOGGER = new CuiLogger(KeyStoreProvider.class);

    @Serial
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
     * (Optional) password for the keystore-key. Due to its nature this is usually
     * only necessary for {@link KeyStoreType#KEY_STORE}
     */
    @Getter
    private final String keyPassword;

    @Getter
    @Singular
    private final Collection<KeyMaterialHolder> keys;

    /**
     * Creates a new {@link KeyStore} using the configured parameters.
     * If key materials are provided, they will be used to create the store.
     * Otherwise, the store will be loaded from the configured file location.
     *
     * @return a new {@link KeyStore} instance
     * @throws IllegalStateException if the store cannot be created or loaded
     */
    public Optional<KeyStore> resolveKeyStore() {
        if (BooleanOperations.areAllTrue(keys.isEmpty(), null == location)) {
            LOGGER.debug("Neither file nor keyMaterial provided, returning Optional#empty");
            return Optional.empty();
        }
        if (null != location) {
            LOGGER.debug("Checking whether configured %s path is readable", location.getAbsolutePath());
            checkState(MorePaths.checkReadablePath(location.toPath(), false, true),
                    "'%s' is not readable check logs for reason", location.getAbsolutePath());
        }
        if (!keys.isEmpty()) {
            return retrieveFromKeys();
        }
        return retrieveFromFile();
    }

    private Optional<KeyStore> retrieveFromFile() {
        LOGGER.debug("Loading keystore from %s", location);
        try (InputStream input = new BufferedInputStream(new FileInputStream(location))) {
            var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(input, getStorePasswordAsCharArray());
            return Optional.of(keyStore);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IllegalStateException(UNABLE_TO_CREATE_KEYSTORE, e);
        }
    }

    private Optional<KeyStore> retrieveFromKeys() {
        LOGGER.debug("Loading keystore from %s", keys);
        var keyStore = createEmptyKeyStore();
        for (KeyMaterialHolder key : keys) {
            LOGGER.debug("Adding Key %s", key);
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
            var cert = cf.generateCertificate(certStream);
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
            var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, getStorePasswordAsCharArray());
            return keyStore;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IllegalStateException(UNABLE_TO_CREATE_KEYSTORE, e);
        }
    }

    /**
     * @return The store password as a character array. If no password is set,
     *         returns an empty array.
     */
    public char[] getStorePasswordAsCharArray() {
        return toCharArray(storePassword);
    }

    /**
     * @return The key password as a character array. If no password is set,
     *         returns an empty array.
     */
    public char[] getKeyPasswordAsCharArray() {
        return toCharArray(keyPassword);
    }

    /**
     * In case of accessing data on the {@link KeyStore} sometimes it is needed to
     * access the defined key-password. If not present the api needs the
     * store-password instead. This is method is a convenience method for dealing
     * with that case.
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
    static char[] toCharArray(String password) {
        if (isEmpty(password)) {
            return new char[0];
        }
        return password.toCharArray();
    }
}
