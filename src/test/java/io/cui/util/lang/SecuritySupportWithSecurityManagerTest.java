package io.cui.util.lang;

import static io.cui.util.lang.SecuritySupport.accessSystemEnv;
import static io.cui.util.lang.SecuritySupport.accessSystemProperties;
import static io.cui.util.lang.SecuritySupport.accessSystemProperty;
import static io.cui.util.lang.SecuritySupport.getContextClassLoader;
import static io.cui.util.lang.SecuritySupport.getDeclaredConstructor;
import static io.cui.util.lang.SecuritySupport.setAccessible;
import static io.cui.util.lang.SecuritySupportTest.TEST_KEY;
import static io.cui.util.lang.SecuritySupportTest.TEST_VALUE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.cui.util.reflect.MoreReflection;
import io.cui.util.reflect.support.FieldNameClass;

/**
 * FIXME Oliver Wolff: Add negative tests / permission denied
 *
 */
class SecuritySupportWithSecurityManagerTest {

    private static TestSecurityManager MANAGER;

    @BeforeAll
    static void initializeSecurityManager() {
        MANAGER = new TestSecurityManager();
    }

    @AfterAll
    static void tearDownSecurityManager() {
        MANAGER.setAllowSecuritySupport(true);
        System.setSecurityManager(null);
    }

    @BeforeEach
    void resetAllowAll() {
        MANAGER.setAllowSecuritySupport(true);
        System.setSecurityManager(MANAGER);
    }

    @Test
    void shouldAccessContextClassLoader() {
        assertTrue(getContextClassLoader().isPresent());
    }

    @Test
    void shouldSetAccessible() {
        Field field = MoreReflection.accessField(FieldNameClass.class, "myField").get();
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
