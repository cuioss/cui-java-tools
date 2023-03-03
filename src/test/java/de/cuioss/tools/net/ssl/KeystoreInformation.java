package de.cuioss.tools.net.ssl;

import java.nio.file.Path;
import java.nio.file.Paths;

import lombok.experimental.UtilityClass;

/**
 * Provide some constants for the testKeystore
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
@SuppressWarnings("javadoc")
public class KeystoreInformation {

    public static final String PASSWORD = "secret";

    public static final Path BASE = Paths.get("src", "test", "resources");

    public static final Path EMPTY_KEY_STORE = BASE.resolve("emptyKeystore.jks");

    public static final Path SINGLE_KEY_STORE = BASE.resolve("singleKeyKeystore.jks");

    public static final Path EMPTY_KEY_STORE_NO_PASSWORD = BASE.resolve("emptyKeystoreNoPassword.jks");

    public static final String SINGLE_KEY_NAME = "test";
}
