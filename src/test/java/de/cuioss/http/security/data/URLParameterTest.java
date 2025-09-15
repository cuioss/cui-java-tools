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
package de.cuioss.http.security.data;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link URLParameter}
 */
class URLParameterTest {

    private static final String PARAM_NAME = "userId";
    private static final String PARAM_VALUE = "12345";

    @Test
    void shouldCreateParameterWithNameAndValue() {
        URLParameter param = new URLParameter(PARAM_NAME, PARAM_VALUE);

        assertEquals(PARAM_NAME, param.name());
        assertEquals(PARAM_VALUE, param.value());
    }

    @Test
    void shouldCreateParameterWithNullValues() {
        URLParameter param1 = new URLParameter(null, PARAM_VALUE);
        URLParameter param2 = new URLParameter(PARAM_NAME, null);
        URLParameter param3 = new URLParameter(null, null);

        assertNull(param1.name());
        assertEquals(PARAM_VALUE, param1.value());

        assertEquals(PARAM_NAME, param2.name());
        assertNull(param2.value());

        assertNull(param3.name());
        assertNull(param3.value());
    }

    @Test
    void shouldAcceptEmptyParameterName() {
        // Records are pure data holders - validation is done by consumers
        URLParameter param1 = new URLParameter("", PARAM_VALUE);
        assertEquals("", param1.name());
        assertEquals(PARAM_VALUE, param1.value());

        // Whitespace-only names should also be accepted
        URLParameter param2 = new URLParameter("   ", PARAM_VALUE);
        assertEquals("   ", param2.name());
        assertEquals(PARAM_VALUE, param2.value());
    }

    @Test
    void shouldAllowNullParameterName() {
        // Null names are allowed for edge cases like "=value"
        URLParameter param = new URLParameter(null, PARAM_VALUE);
        assertNull(param.name());
        assertEquals(PARAM_VALUE, param.value());
    }

    @Test
    void shouldCreateParameterWithEmptyValue() {
        URLParameter param = URLParameter.withEmptyValue("flag");

        assertEquals("flag", param.name());
        assertEquals("", param.value());
    }

    @Test
    void shouldDetectParameterWithName() {
        URLParameter withName = new URLParameter(PARAM_NAME, PARAM_VALUE);
        URLParameter withoutName = new URLParameter(null, PARAM_VALUE);

        assertTrue(withName.hasName());
        assertFalse(withoutName.hasName());
        // Note: Empty name is now rejected by constructor validation
    }

    @Test
    void shouldDetectParameterWithValue() {
        URLParameter withValue = new URLParameter(PARAM_NAME, PARAM_VALUE);
        URLParameter withoutValue = new URLParameter(PARAM_NAME, null);
        URLParameter withEmptyValue = new URLParameter(PARAM_NAME, "");

        assertTrue(withValue.hasValue());
        assertFalse(withoutValue.hasValue());
        assertFalse(withEmptyValue.hasValue());
    }

    @Test
    void shouldDetectFlagParameters() {
        URLParameter normalParam = new URLParameter("name", "value");
        URLParameter flagParam1 = new URLParameter("flag", "");
        URLParameter flagParam2 = new URLParameter("flag", null);
        URLParameter invalidFlag = new URLParameter(null, "value");

        assertFalse(normalParam.isFlag());
        assertTrue(flagParam1.isFlag());
        assertTrue(flagParam2.isFlag());
        assertFalse(invalidFlag.isFlag()); // No name, so not a flag
    }

    @Test
    void shouldReturnNameOrDefault() {
        URLParameter withName = new URLParameter(PARAM_NAME, PARAM_VALUE);
        URLParameter withoutName = new URLParameter(null, PARAM_VALUE);

        assertEquals(PARAM_NAME, withName.nameOrDefault("default"));
        assertEquals("default", withoutName.nameOrDefault("default"));
    }

    @Test
    void shouldReturnValueOrDefault() {
        URLParameter withValue = new URLParameter(PARAM_NAME, PARAM_VALUE);
        URLParameter withoutValue = new URLParameter(PARAM_NAME, null);

        assertEquals(PARAM_VALUE, withValue.valueOrDefault("default"));
        assertEquals("default", withoutValue.valueOrDefault("default"));
    }

    @Test
    void shouldGenerateParameterString() {
        URLParameter normalParam = new URLParameter("name", "value");
        URLParameter flagParam = new URLParameter("flag", "");
        URLParameter nullValueParam = new URLParameter("key", null);
        URLParameter nullNameParam = new URLParameter(null, "value");
        URLParameter nullBothParam = new URLParameter(null, null);

        assertEquals("name=value", normalParam.toParameterString());
        assertEquals("flag", flagParam.toParameterString());
        assertEquals("key", nullValueParam.toParameterString());
        assertEquals("=value", nullNameParam.toParameterString());
        assertEquals("", nullBothParam.toParameterString());
    }

    @Test
    void shouldCreateParameterWithNewName() {
        URLParameter original = new URLParameter(PARAM_NAME, PARAM_VALUE);
        URLParameter renamed = original.withName("newName");

        assertEquals("newName", renamed.name());
        assertEquals(PARAM_VALUE, renamed.value());
        assertEquals(PARAM_NAME, original.name()); // Original unchanged
    }

    @Test
    void shouldCreateParameterWithNewValue() {
        URLParameter original = new URLParameter(PARAM_NAME, PARAM_VALUE);
        URLParameter newValue = original.withValue("newValue");

        assertEquals(PARAM_NAME, newValue.name());
        assertEquals("newValue", newValue.value());
        assertEquals(PARAM_VALUE, original.value()); // Original unchanged
    }

    @Test
    void shouldSupportEquality() {
        URLParameter param1 = new URLParameter(PARAM_NAME, PARAM_VALUE);
        URLParameter param2 = new URLParameter(PARAM_NAME, PARAM_VALUE);
        URLParameter param3 = new URLParameter("other", PARAM_VALUE);

        assertEquals(param1, param2);
        assertNotEquals(param1, param3);
        assertEquals(param1.hashCode(), param2.hashCode());
    }

    @Test
    void shouldSupportToString() {
        URLParameter param = new URLParameter(PARAM_NAME, PARAM_VALUE);
        String string = param.toString();

        assertTrue(string.contains(PARAM_NAME));
        assertTrue(string.contains(PARAM_VALUE));
    }

    @Test
    void shouldHandleSpecialCharacters() {
        URLParameter param = new URLParameter("special&name", "value with spaces");

        assertEquals("special&name", param.name());
        assertEquals("value with spaces", param.value());
        assertEquals("special&name=value with spaces", param.toParameterString());
    }

    @Test
    void shouldHandleUnicodeCharacters() {
        URLParameter param = new URLParameter("名前", "値");

        assertEquals("名前", param.name());
        assertEquals("値", param.value());
        assertTrue(param.hasName());
        assertTrue(param.hasValue());
    }

    @Test
    void shouldHandleNullVsValue() {
        URLParameter nullName = new URLParameter(null, "value");
        URLParameter emptyValue = new URLParameter("name", "");
        URLParameter nullValue = new URLParameter("name", null);

        assertFalse(nullName.hasName());
        assertFalse(emptyValue.hasValue());
        assertFalse(nullValue.hasValue());

        assertEquals("default", nullName.nameOrDefault("default"));
        assertEquals("", emptyValue.valueOrDefault("default"));
        assertEquals("default", nullValue.valueOrDefault("default"));

        // Note: Empty string names are now rejected by constructor validation
    }

    @Test
    void shouldHandleLongValues() {
        String longName = generateTestContent("a", 1000);
        String longValue = generateTestContent("b", 1000);
        URLParameter param = new URLParameter(longName, longValue);

        assertEquals(longName, param.name());
        assertEquals(longValue, param.value());
        assertTrue(param.hasName());
        assertTrue(param.hasValue());
    }

    @Test
    void shouldBeImmutable() {
        URLParameter original = new URLParameter(PARAM_NAME, PARAM_VALUE);

        URLParameter withNewName = original.withName("new");
        URLParameter withNewValue = original.withValue("new");

        // Original should be unchanged
        assertEquals(PARAM_NAME, original.name());
        assertEquals(PARAM_VALUE, original.value());

        // New instances should have changes
        assertEquals("new", withNewName.name());
        assertEquals(PARAM_VALUE, withNewName.value());
        assertEquals(PARAM_NAME, withNewValue.name());
        assertEquals("new", withNewValue.value());
    }

    @Test
    void shouldHandleEdgeCasesInParameterString() {
        URLParameter justEquals = new URLParameter("=", "=");
        URLParameter withEquals = new URLParameter("key=name", "value=data");

        assertEquals("===", justEquals.toParameterString());
        assertEquals("key=name=value=data", withEquals.toParameterString());
    }

    /**
     * QI-17: Generate realistic test content instead of using .repeat().
     * Creates varied content for URL parameter testing.
     */
    private String generateTestContent(String base, int length) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < length; i++) {
            result.append(base);
            // Add variation every 50 characters for more realistic testing
            if (i % 50 == 49) {
                result.append(i % 10);
            }
        }
        return result.toString();
    }
}