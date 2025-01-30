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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.cuioss.tools.net.ssl.KeyMaterialHolder.KeyMaterialHolderBuilder;
import de.cuioss.tools.support.Generators;
import org.junit.jupiter.api.Test;

class KeyMaterialHolderTest {

    @Test
    void shouldBuildWithKeyMaterialOnly() {
        assertNotNull(withRandomKeyMaterial());

        var builder = KeyMaterialHolder.builder();
        assertThrows(NullPointerException.class, builder::build);
    }

    @Test
    void shouldHandleHolderType() {
        assertEquals(KeyHolderType.SINGLE_KEY, withRandomKeyMaterial().build().getKeyHolderType());
        assertEquals(KeyHolderType.KEY_STORE,
                withRandomKeyMaterial().keyHolderType(KeyHolderType.KEY_STORE).build().getKeyHolderType());
    }

    @Test
    void shouldHandleAlgorithm() {
        assertEquals(KeyAlgorithm.UNDEFINED, withRandomKeyMaterial().build().getKeyAlgorithm());
        assertEquals(KeyAlgorithm.ECDSA_P_256,
                withRandomKeyMaterial().keyAlgorithm(KeyAlgorithm.ECDSA_P_256).build().getKeyAlgorithm());
    }

    @Test
    void shouldHandlePassword() {
        var noPassword = withRandomKeyMaterial().build();
        assertNull(noPassword.getKeyPassword());
        assertNotNull(noPassword.getKeyPasswordAsCharArray());

        var password = Generators.randomString();
        var withPassword = withRandomKeyMaterial().keyPassword(password).build();
        assertEquals(password, withPassword.getKeyPassword());
        assertArrayEquals(password.toCharArray(), withPassword.getKeyPasswordAsCharArray());
    }

    @Test
    void serializesKeyMaterial() {
        final var kmh = withRandomKeyMaterial().build();
        final var roundtripResult = KeyMaterialHolder
                .deserializeKeyMaterial(KeyMaterialHolder.serializeKeyMaterial(kmh.getKeyMaterial()));
        assertArrayEquals(kmh.getKeyMaterial(), roundtripResult, "byte arrays should be equal");
    }

    private byte[] randomKeyMaterial() {
        return Generators.generateTestData(100);
    }

    private KeyMaterialHolderBuilder withRandomKeyMaterial() {
        return KeyMaterialHolder.builder().keyMaterial(randomKeyMaterial());
    }
}
