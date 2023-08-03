package de.cuioss.tools.net.ssl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.net.ssl.KeyMaterialHolder.KeyMaterialHolderBuilder;
import de.cuioss.tools.support.Generators;

class KeyMaterialHolderTest {

    @Test
    void shouldBuildWithKeyMaterialOnly() {
        assertNotNull(withRandomKeyMaterial());

        var builder = KeyMaterialHolder.builder();
        assertThrows(NullPointerException.class, () -> {
            builder.build();
        });
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
