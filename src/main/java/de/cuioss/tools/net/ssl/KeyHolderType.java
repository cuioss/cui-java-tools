package de.cuioss.tools.net.ssl;

/**
 * Used in the context of {@link KeyMaterialHolder}. Defines the type of the
 * contained Key.
 *
 * @author Oliver Wolff
 *
 */
public enum KeyHolderType {

    /**
     * The byte[] represents a serialized keyStore. Therefore, the optional
     * {@link KeyMaterialHolder#getKeyPassword()} represents the store-password.
     */
    KEY_STORE,

    /**
     * The byte-array represents a single key. This is the default for
     * {@link KeyMaterialHolder}
     */
    SINGLE_KEY
}
