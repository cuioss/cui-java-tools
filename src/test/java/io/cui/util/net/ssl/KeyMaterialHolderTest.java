package io.cui.util.net.ssl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import io.cui.util.net.ssl.KeyMaterialHolder.KeyMaterialHolderBuilder;
import io.cui.util.support.Generators;

class KeyMaterialHolderTest {

    @Test
    void shouldBuildWithKeyMaterialOnly() {
        assertNotNull(withRandomKeyMaterial());

        KeyMaterialHolderBuilder builder = KeyMaterialHolder.builder();
        assertThrows(NullPointerException.class, () -> {
            builder.build();
        });
    }

    @Test
    void shouldHandleHolderType() {
        assertEquals(KeyHolderType.SINGLE_KEY, withRandomKeyMaterial().build().getKeyHolderType());
        assertEquals(KeyHolderType.KEY_STORE, withRandomKeyMaterial()
                        .keyHolderType(KeyHolderType.KEY_STORE).build().getKeyHolderType());
    }

    @Test
    void shouldHandleAlgorithm() {
        assertEquals(KeyAlgorithm.UNDEFINED, withRandomKeyMaterial().build().getKeyAlgorithm());
        assertEquals(KeyAlgorithm.ECDSA_P_256, withRandomKeyMaterial()
                        .keyAlgorithm(KeyAlgorithm.ECDSA_P_256).build().getKeyAlgorithm());
    }

    @Test
    void shouldHandlePassword() {
        KeyMaterialHolder noPassword = withRandomKeyMaterial().build();
        assertNull(noPassword.getKeyPassword());
        assertNotNull(noPassword.getKeyPasswordAsCharArray());

        String password = Generators.randomString();
        KeyMaterialHolder withPassword = withRandomKeyMaterial().keyPassword(password).build();
        assertEquals(password, withPassword.getKeyPassword());
        assertArrayEquals(password.toCharArray(), withPassword.getKeyPasswordAsCharArray());
    }

    @Test
    void serializesKeyMaterial() {
        final KeyMaterialHolder kmh = withRandomKeyMaterial().build();
        final byte[] roundtripResult = KeyMaterialHolder.deserializeKeyMaterial(
            KeyMaterialHolder.serializeKeyMaterial(
                kmh.getKeyMaterial()));
        assertTrue(Arrays.equals(kmh.getKeyMaterial(), roundtripResult),
            "byte arrays should be equal");
    }

    private byte[] randomKeyMaterial() {
        return Generators.generateTestData(100);
    }

    private KeyMaterialHolderBuilder withRandomKeyMaterial() {
        return KeyMaterialHolder.builder()
            .keyMaterial(randomKeyMaterial());
    }
}
