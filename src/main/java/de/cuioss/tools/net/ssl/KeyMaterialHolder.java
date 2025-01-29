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

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.Base64;

/**
 * Runtime representation of key-material. The actual key is provided as byte[].
 * An optional keyPassword is available as well.
 *
 * @author Oliver Wolff
 */
@Builder
@EqualsAndHashCode(exclude = {"keyMaterial", "keyPassword"}, doNotUseGetters = true)
@ToString(exclude = {"keyMaterial", "keyPassword"}, doNotUseGetters = true)
public final class KeyMaterialHolder implements Serializable {

    @Serial
    private static final long serialVersionUID = -3125499798220509939L;

    @Getter
    private final byte @NonNull [] keyMaterial;

    /**
     * (Optional) password for the key, or in case of
     * {@link KeyHolderType#KEY_STORE} for the store.
     */
    @Getter
    private final String keyPassword;

    /**
     * Optional: An arbitrary name for displaying the key in an ui or logging
     * context.
     */
    @Getter
    private final String name;

    /**
     * Optional: additional information transporting some context-information.
     */
    @Getter
    private final String description;

    /**
     * Optional: An alias name for a given key.
     */
    @Getter
    private final String keyAlias;

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
     * @return NPE-safe char-array representation of #getKeyPassword().
     * If keyPassword is {@code null} or empty it returns an empty char[],
     * never {@code null}
     */
    @SuppressWarnings("javaarchitecture:S7027") // owolff: Circular dependency not a problem here: Utility-only
    public char[] getKeyPasswordAsCharArray() {
        return KeyStoreProvider.toCharArray(keyPassword);
    }

    /**
     * @param serializedKeyMaterial the Base64 encoded key material
     * @return Raw i.e., original key material
     * @throws IllegalArgumentException if serializedKeyMaterial is not Base64
     *                                  encoded
     */
    public static byte[] deserializeKeyMaterial(final String serializedKeyMaterial) {
        return Base64.getDecoder().decode(serializedKeyMaterial);
    }

    /**
     * @param keyMaterial Raw i.e., original key material
     * @return Base64 encoded key material
     */
    public static String serializeKeyMaterial(final byte[] keyMaterial) {
        return Base64.getEncoder().encodeToString(keyMaterial);
    }
}
