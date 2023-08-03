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
package de.cuioss.tools.lang;

import static de.cuioss.tools.lang.SecuritySupport.accessSystemEnv;
import static de.cuioss.tools.lang.SecuritySupport.accessSystemProperties;
import static de.cuioss.tools.lang.SecuritySupport.accessSystemProperty;
import static de.cuioss.tools.lang.SecuritySupport.getContextClassLoader;
import static de.cuioss.tools.lang.SecuritySupport.getDeclaredConstructor;
import static de.cuioss.tools.lang.SecuritySupport.setAccessible;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.reflect.MoreReflection;
import de.cuioss.tools.reflect.support.FieldNameClass;

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
