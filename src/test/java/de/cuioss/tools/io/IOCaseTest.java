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
package de.cuioss.tools.io;

import de.cuioss.tools.support.Generators;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link IOCase} class focusing on case sensitivity handling in file operations.
 * Based on Apache Commons IO test cases.
 */
class IOCaseTest {

    private static final boolean WINDOWS = File.separatorChar == '\\';

    @ParameterizedTest
    @CsvSource({
            "Sensitive,SENSITIVE",
            "Insensitive,INSENSITIVE",
            "System,SYSTEM"
    })
    void shouldResolveValidCaseNames(String name, IOCase expected) {
        assertEquals(expected, IOCase.forName(name));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Blah", ""})
    void shouldFailForInvalidCaseNames(String invalidName) {
        assertThrows(IllegalArgumentException.class, () -> IOCase.forName(invalidName));
    }

    @Test
    void shouldFailForNullCaseName() {
        assertThrows(IllegalArgumentException.class, () -> IOCase.forName(null));
    }

    @Test
    void shouldMaintainSingletonThroughSerialization() throws Exception {
        assertSame(IOCase.SENSITIVE, serialize(IOCase.SENSITIVE));
        assertSame(IOCase.INSENSITIVE, serialize(IOCase.INSENSITIVE));
        assertSame(IOCase.SYSTEM, serialize(IOCase.SYSTEM));
    }

    @ParameterizedTest
    @EnumSource(IOCase.class)
    void shouldProvideConsistentNames(IOCase ioCase) {
        assertEquals(ioCase.getName(), ioCase.toString());
    }

    @Test
    void shouldReflectSystemCaseSensitivity() {
        assertTrue(IOCase.SENSITIVE.isCaseSensitive());
        assertFalse(IOCase.INSENSITIVE.isCaseSensitive());
        assertEquals(!WINDOWS, IOCase.SYSTEM.isCaseSensitive());
    }

    @Test
    void shouldHandleCompareToEdgeCases() {
        var testString = Generators.randomString();
        assertTrue(IOCase.SENSITIVE.checkCompareTo(testString, "") > 0);
        assertTrue(IOCase.SENSITIVE.checkCompareTo("", testString) < 0);
        assertEquals(0, IOCase.SENSITIVE.checkCompareTo("", ""));

        assertThrows(NullPointerException.class, () -> IOCase.SENSITIVE.checkCompareTo(testString, null));
        assertThrows(NullPointerException.class, () -> IOCase.SENSITIVE.checkCompareTo(null, testString));
        assertThrows(NullPointerException.class, () -> IOCase.SENSITIVE.checkCompareTo(null, null));
    }

    @Test
    void shouldHandleCompareToWithDifferentCases() {
        assertEquals(0, IOCase.SENSITIVE.checkCompareTo("ABC", "ABC"));
        assertTrue(IOCase.SENSITIVE.checkCompareTo("ABC", "abc") < 0);
        assertTrue(IOCase.SENSITIVE.checkCompareTo("abc", "ABC") > 0);

        assertEquals(0, IOCase.INSENSITIVE.checkCompareTo("ABC", "ABC"));
        assertEquals(0, IOCase.INSENSITIVE.checkCompareTo("ABC", "abc"));
        assertEquals(0, IOCase.INSENSITIVE.checkCompareTo("abc", "ABC"));

        assertEquals(0, IOCase.SYSTEM.checkCompareTo("ABC", "ABC"));
        assertEquals(WINDOWS, IOCase.SYSTEM.checkCompareTo("ABC", "abc") == 0);
        assertEquals(WINDOWS, IOCase.SYSTEM.checkCompareTo("abc", "ABC") == 0);
    }

    @Test
    void shouldHandleEqualsEdgeCases() {
        var testString = Generators.randomString();
        assertFalse(IOCase.SENSITIVE.checkEquals(testString, ""));
        assertTrue(IOCase.SENSITIVE.checkEquals("", ""));

        assertThrows(NullPointerException.class, () -> IOCase.SENSITIVE.checkEquals(testString, null));
        assertThrows(NullPointerException.class, () -> IOCase.SENSITIVE.checkEquals(null, testString));
        assertThrows(NullPointerException.class, () -> IOCase.SENSITIVE.checkEquals(null, null));
    }

    @Test
    void shouldHandleEqualsWithDifferentCases() {
        assertTrue(IOCase.SENSITIVE.checkEquals("ABC", "ABC"));
        assertFalse(IOCase.SENSITIVE.checkEquals("ABC", "Abc"));

        assertTrue(IOCase.INSENSITIVE.checkEquals("ABC", "ABC"));
        assertTrue(IOCase.INSENSITIVE.checkEquals("ABC", "Abc"));

        assertTrue(IOCase.SYSTEM.checkEquals("ABC", "ABC"));
        assertEquals(WINDOWS, IOCase.SYSTEM.checkEquals("ABC", "Abc"));
    }

    @Test
    void shouldHandleStartsWithEdgeCases() {
        var testString = Generators.randomString();
        assertTrue(IOCase.SENSITIVE.checkStartsWith(testString, ""));
        assertFalse(IOCase.SENSITIVE.checkStartsWith("", testString));
        assertTrue(IOCase.SENSITIVE.checkStartsWith("", ""));

        assertThrows(NullPointerException.class, () -> IOCase.SENSITIVE.checkStartsWith(testString, null));
        assertThrows(NullPointerException.class, () -> IOCase.SENSITIVE.checkStartsWith(null, testString));
        assertThrows(NullPointerException.class, () -> IOCase.SENSITIVE.checkStartsWith(null, null));
    }

    @ParameterizedTest
    @CsvSource({
            "ABC,A,true",
            "ABC,AB,true",
            "ABC,ABC,true",
            "ABC,BC,false",
            "ABC,C,false",
            "ABC,ABCD,false"
    })
    void shouldHandleStartsWithVariousPrefixes(String input, String prefix, boolean expected) {
        assertEquals(expected, IOCase.SENSITIVE.checkStartsWith(input, prefix));
    }

    @Test
    void shouldHandleStartsWithDifferentCases() {
        assertTrue(IOCase.SENSITIVE.checkStartsWith("ABC", "ABC"));
        assertFalse(IOCase.SENSITIVE.checkStartsWith("ABC", "abc"));

        assertTrue(IOCase.INSENSITIVE.checkStartsWith("ABC", "ABC"));
        assertTrue(IOCase.INSENSITIVE.checkStartsWith("ABC", "abc"));

        assertTrue(IOCase.SYSTEM.checkStartsWith("ABC", "ABC"));
        assertEquals(WINDOWS, IOCase.SYSTEM.checkStartsWith("ABC", "abc"));
    }

    private IOCase serialize(IOCase value) throws Exception {
        try (var baos = new ByteArrayOutputStream();
             var oos = new ObjectOutputStream(baos)) {
            oos.writeObject(value);
            try (var bais = new ByteArrayInputStream(baos.toByteArray());
                 var ois = new ObjectInputStream(bais)) {
                return (IOCase) ois.readObject();
            }
        }
    }
}
