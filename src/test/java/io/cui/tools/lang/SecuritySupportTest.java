package io.cui.tools.lang;

import static io.cui.tools.lang.SecuritySupport.accessSystemEnv;
import static io.cui.tools.lang.SecuritySupport.accessSystemProperties;
import static io.cui.tools.lang.SecuritySupport.accessSystemProperty;
import static io.cui.tools.lang.SecuritySupport.getContextClassLoader;
import static io.cui.tools.lang.SecuritySupport.getDeclaredConstructor;
import static io.cui.tools.lang.SecuritySupport.setAccessible;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;

import org.junit.jupiter.api.Test;

import io.cui.tools.reflect.MoreReflection;
import io.cui.tools.reflect.support.FieldNameClass;

class SecuritySupportTest {

    static final String TEST_VALUE = "testValue";
    static final String TEST_KEY = "testKey";

    @Test
    void shouldAccessContextClassLoader() {
        assertTrue(getContextClassLoader().isPresent());
    }

    @Test
    void shouldSetAccessible() {
        var field = MoreReflection.accessField(FieldNameClass.class, "myField").get();
        assertFalse(field.isAccessible());

        setAccessible(field, true);
        assertTrue(field.isAccessible());

        setAccessible(field, false);
        assertFalse(field.isAccessible());
    }

    @Test
    void shouldAccessDeclaredConstructor() throws NoSuchMethodException {
        Constructor<? extends String> constructor = getDeclaredConstructor(String.class, String.class);
        assertNotNull(constructor);

        assertThrows(NoSuchMethodException.class, () -> getDeclaredConstructor(String.class, Thread.class));
    }

    @Test
    void shouldAccessSystemProperty() {
        assertFalse(accessSystemProperty(null).isPresent());
        System.setProperty(TEST_KEY, TEST_VALUE);
        assertTrue(accessSystemProperty(TEST_KEY).isPresent());
        assertEquals(TEST_VALUE, accessSystemProperty(TEST_KEY).get());
    }

    @Test
    void shouldAccessSystemEnv() {
        assertFalse(accessSystemEnv().isEmpty());
    }

    @Test
    void shouldAccessSystemProperties() {
        assertFalse(accessSystemProperties().isEmpty());
    }

}
