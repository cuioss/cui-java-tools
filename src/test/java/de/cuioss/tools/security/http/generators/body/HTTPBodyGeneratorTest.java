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
package de.cuioss.tools.security.http.generators.body;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.data.HTTPBody;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link HTTPBodyGenerator}
 */
@EnableGeneratorController
class HTTPBodyGeneratorTest {

    @ParameterizedTest
    @TypeGeneratorSource(value = HTTPBodyGenerator.class, count = 100)
    @DisplayName("Generator should produce valid non-null HTTP bodies")
    void shouldGenerateValidOutput(HTTPBody generatedValue) {
        assertNotNull(generatedValue, "Generator must not produce null values");
        assertNotNull(generatedValue.content(), "HTTPBody content should not be null");
        assertNotNull(generatedValue.contentType(), "HTTPBody contentType should not be null");
        assertNotNull(generatedValue.encoding(), "HTTPBody encoding should not be null");
        
        // Content can be empty (that's valid for HTTP bodies), just not null
        // Verify record structure works correctly
        String toString = generatedValue.toString();
        assertTrue(toString.contains("HTTPBody"), "toString should contain record name");
        
        // Test equals and hashCode work (records auto-generate these)
        HTTPBody duplicate = new HTTPBody(generatedValue.content(), generatedValue.contentType(), generatedValue.encoding());
        assertEquals(generatedValue, duplicate, "Equal bodies should be equal");
        assertEquals(generatedValue.hashCode(), duplicate.hashCode(), "Equal bodies should have same hash code");
    }
}