/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.lang;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.Serializable;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("DataFlowIssue")
class MoreObjectsTest {

    private static final String HELLO = "Hello";

    @Test
    void requireTypeShouldPassThroughOnFittingTypes() {
        assertNotNull(MoreObjects.requireType(0, Serializable.class));
        assertNotNull(MoreObjects.requireType(1, Number.class));
        assertNotNull(MoreObjects.requireType(HELLO, String.class));
    }

    @Test
    void requireTypeShouldHandleInvalidTypes() {
        assertThrows(IllegalArgumentException.class, () ->
                MoreObjects.requireType(null, null));
        assertThrows(IllegalArgumentException.class, () ->
                MoreObjects.requireType(HELLO, null));
        assertThrows(IllegalArgumentException.class, () ->
                MoreObjects.requireType(null, Serializable.class));
        assertThrows(IllegalArgumentException.class, () ->
                MoreObjects.requireType(HELLO, Number.class));
    }

    @Test
    void shouldDetectNullValues() {
        assertTrue(MoreObjects.allNonNull());
        assertTrue(MoreObjects.allNonNull(""));
        assertTrue(MoreObjects.allNonNull("", 1, new File("")));
        assertFalse(MoreObjects.allNonNull("", null, new File("")));
        assertFalse(MoreObjects.allNonNull("", null));
        assertFalse(MoreObjects.allNonNull((String) null));
    }

    @Test
    void shouldDetectNonNullValues() {
        assertTrue(MoreObjects.allNull());
        assertFalse(MoreObjects.allNull(""));
        assertFalse(MoreObjects.allNull("", 1, new File("")));
        assertFalse(MoreObjects.allNull("", null, new File("")));
        assertFalse(MoreObjects.allNull("", null));
        assertTrue(MoreObjects.allNull(null, null));
        assertTrue(MoreObjects.allNull((String) null));
    }

    @SuppressWarnings("ConstantValue")
    @Test
    void firstNonNull() {
        assertEquals("", MoreObjects.firstNonNull(null, ""));
        final var firstNonNullGenerics = MoreObjects.firstNonNull(null, null, "123", "456");
        assertEquals("123", firstNonNullGenerics);
        assertEquals("123", MoreObjects.firstNonNull("123", null, "456", null));
        assertEquals(Boolean.TRUE, MoreObjects.firstNonNull(Boolean.TRUE));

        // Explicitly pass in an empty array of an Object type to ensure the compiler doesn't
        // complain of
        // unchecked generic
        // array creation
        assertNull(MoreObjects.firstNonNull());

        // Cast to Object in line below ensures the compiler doesn't complain of unchecked
        // generic array
        // creation
        assertNull(MoreObjects.firstNonNull(null, null));

        assertNull(MoreObjects.firstNonNull((Object) null));
        assertNull(MoreObjects.firstNonNull((Object[]) null));
    }

    @Test
    void getFirstNonNull() {
        // first non-null
        assertEquals("", MoreObjects.getFirstNonNull(() -> null, () -> ""));
        // first encountered value is used
        assertEquals("1", MoreObjects.getFirstNonNull(() -> null, () -> "1", () -> "2", () -> null));
        assertEquals("123", MoreObjects.getFirstNonNull(() -> "123", () -> null, () -> "456"));
        // don't evaluate suppliers after the first value is found
        assertEquals("123", MoreObjects.getFirstNonNull(() -> null, () -> "123",
                () -> fail("Supplier after first non-null value should not be evaluated")));
        // supplier returning null and null supplier both results in null
        assertNull(MoreObjects.getFirstNonNull(null, () -> null));
        // Explicitly pass in an empty array of an Object type to ensure the compiler doesn't
        // complain of
        // unchecked generic
        // array creation
        assertNull(MoreObjects.getFirstNonNull());
        // supplier is null
        assertNull(MoreObjects.getFirstNonNull((Supplier<Object>) null));
        // varargs array itself is null
        assertNull(MoreObjects.getFirstNonNull((Supplier<Object>[]) null));
        // test different types
        assertEquals(1, MoreObjects.getFirstNonNull(() -> null, () -> 1));
        assertEquals(Boolean.TRUE, MoreObjects.getFirstNonNull(() -> null, () -> Boolean.TRUE));
    }
}
