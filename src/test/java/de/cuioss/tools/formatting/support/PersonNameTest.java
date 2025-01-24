package de.cuioss.tools.formatting.support;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @ParameterizedTest(name = "Property {0} should be handled correctly")
    @MethodSource("provideTestCases")
    void shouldHandleProperties(String propertyName, String value, PersonName person) {
        Map<String, Serializable> values = person.getAvailablePropertyValues();
        assertEquals(value, values.get(propertyName));
    }

    private static Stream<Arguments> provideTestCases() {
        return Stream.of(TEST_CASES)
                .map(holder -> Arguments.of(holder.propertyName(), holder.value(), holder.person()));
    }

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


    private record CaseHolder(String propertyName, String value, PersonName person) {
    }
}
