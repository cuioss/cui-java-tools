package io.cui.tools.net.ssl;

import java.io.Serializable;
import java.util.Base64;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

/**
 * Runtime representation of key-material. The actual key is provided as byte[]. An optional
 * keyPassword is available as well.
 *
 * @author Oliver Wolff
 *
 */
@Builder
@EqualsAndHashCode(exclude = { "keyMaterial", "keyPassword" }, doNotUseGetters = true)
@ToString(exclude = { "keyMaterial", "keyPassword" }, doNotUseGetters = true)
public final class KeyMaterialHolder implements Serializable {

    private static final long serialVersionUID = -3125499798220509939L;

    @Getter
    @NonNull
    private final byte[] keyMaterial;

    /**
     * (Optional) password for the key, or in case of {@link KeyHolderType#KEY_STORE} for the store.
     */
    @Getter
    private final String keyPassword;

    /** Optional: An arbitrary name for displaying the key in an ui or logging context. */
    @Getter
    private String name;

    /** Optional: additional information transporting some context-information. */
    @Getter
    private String description;

    /** Optional: An alias name for a given key. */
    @Getter
    private String keyAlias;

    @Getter
    @Builder.Default
    @SuppressWarnings("squid:S1170") // owolff: False positive: This is input for @Builder, no
    // constant, especially not public
    private final KeyHolderType keyHolderType = KeyHolderType.SINGLE_KEY;

    @Getter
    @Builder.Default
    @SuppressWarnings("squid:S1170") // owolff: False positive: This is input for @Builder, no
    // constant, especially not public
    private final KeyAlgorithm keyAlgorithm = KeyAlgorithm.UNDEFINED;

    /**
     * @return NPE-safe char-array representation of {@link #getKeyPassword()}. If keyPassword is
     *         {@code null} or empty it returns an empty char[], never {@code null}
     */
    public char[] getKeyPasswordAsCharArray() {
        return KeyStoreProvider.toCharArray(keyPassword);
    }

    /**
     * @param serializedKeyMaterial the Base64 encoded key material
     *
     * @return Raw i.e. original key material
     * @throws IllegalArgumentException if serializedKeyMaterial is not Base64 encoded
     */
    public static byte[] deserializeKeyMaterial(final String serializedKeyMaterial) {
        return Base64.getDecoder().decode(serializedKeyMaterial);
    }

    /**
     * @param keyMaterial Raw i.e. original key material
     *
     * @return Base64 encoded key material
     */
    public static String serializeKeyMaterial(final byte[] keyMaterial) {
        return Base64.getEncoder().encodeToString(keyMaterial);
    }
}
