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
package de.cuioss.tools.formatting.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.cuioss.tools.support.Generators;
import de.cuioss.tools.support.TypedGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.Serializable;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Test class for {@link PersonName} which verifies:
 * <ul>
 *   <li>Property support and retrieval</li>
 *   <li>Builder functionality</li>
 *   <li>Value handling for all name components</li>
 * </ul>
 */
@DisplayName("PersonName Tests")
class PersonNameTest {

    private static final TypedGenerator<String> STRING_GENERATOR = Generators::randomString;
    private static final CaseHolder[] TEST_CASES = createTestCases();

    private PersonName underTest;

    @BeforeEach
    void setUp() {
        underTest = PersonName.builder()
                .familyName(STRING_GENERATOR.next())
                .givenName(STRING_GENERATOR.next())
                .build();
    }

    /**
     * Verifies that all defined properties.
     * are properly supported and accessible.
     */
    @Test
    @DisplayName("Should support all defined properties")
    void shouldSupportAllProperties() {
        var supportedProps = underTest.getSupportedPropertyNames();
        assertNotNull(supportedProps);
        assertTrue(supportedProps.contains("familyName"));
        assertTrue(supportedProps.contains("givenName"));
        assertTrue(supportedProps.contains("middleName"));
        // Add more assertions for other properties
    }

    /**
     * Tests property value handling using parameterized test cases.
     * Each test case verifies that a specific property is correctly stored and retrieved.
     *
     * @param propertyName The name of the property being tested
     * @param value        The test value for the property
     * @param person       The PersonName instance with the test value set
     */
    @ParameterizedTest(name = "Property {0} should be handled correctly")
    @MethodSource("provideTestCases")
    void shouldHandleProperties(String propertyName, String value, PersonName person) {
        Map<String, Serializable> values = person.getAvailablePropertyValues();
        assertEquals(value, values.get(propertyName));
    }

    /**
     * Provides test cases for property value handling.
     * Each test case consists of:
     * <ul>
     *   <li>Property name to test</li>
     *   <li>Test value</li>
     *   <li>PersonName instance with only that property set</li>
     * </ul>
     *
     * @return Stream of test case arguments
     */
    private static Stream<Arguments> provideTestCases() {
        return Stream.of(TEST_CASES)
                .map(holder -> Arguments.of(holder.propertyName(), holder.value(), holder.person()));
    }

    /**
     * Creates an array of test cases covering all essential name components.
     * Each case tests a single property in isolation to ensure proper value handling.
     *
     * @return Array of CaseHolder instances for testing
     */
    private static CaseHolder[] createTestCases() {
        String testValue = STRING_GENERATOR.next();
        return new CaseHolder[]{
                new CaseHolder("familyName", testValue,
                        PersonName.builder().familyName(testValue).build()),
                new CaseHolder("givenName", testValue,
                        PersonName.builder().givenName(testValue).build()),
                new CaseHolder("middleName", testValue,
                        PersonName.builder().middleName(testValue).build()),
                new CaseHolder("academicPrefix", testValue,
                        PersonName.builder().academicPrefix(testValue).build()),
                new CaseHolder("academicSuffix", testValue,
                        PersonName.builder().academicSuffix(testValue).build()),
                new CaseHolder("professionalPrefix", testValue,
                        PersonName.builder().professionalPrefix(testValue).build()),
                new CaseHolder("professionalSuffix", testValue,
                        PersonName.builder().professionalSuffix(testValue).build())
        };
    }

    /**
     * Record holding test case data for property testing.
     *
     * @param propertyName Name of the property being tested
     * @param value        Test value for the property
     * @param person       PersonName instance with the test value set
     */
    private record CaseHolder(String propertyName, String value, PersonName person) {
    }
}
