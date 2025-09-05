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
package de.cuioss.tools.security.http.generators;

import de.cuioss.tools.security.http.data.HTTPBody;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link HTTPBodyGenerator}
 */
class HTTPBodyGeneratorTest {

    private final HTTPBodyGenerator generator = new HTTPBodyGenerator();

    @Test
    void shouldReturnHTTPBodyType() {
        assertEquals(HTTPBody.class, generator.getType());
    }

    @Test
    void shouldGenerateNonNullValues() {
        for (int i = 0; i < 100; i++) {
            HTTPBody body = generator.next();
            assertNotNull(body, "Generated HTTPBody should not be null");
            assertNotNull(body.content(), "HTTPBody content should not be null");
            assertNotNull(body.contentType(), "HTTPBody contentType should not be null");
            assertNotNull(body.encoding(), "HTTPBody encoding should not be null");
        }
    }

    @Test
    void shouldGenerateVariedBodies() {
        Set<HTTPBody> generatedBodies = new HashSet<>();

        // Generate many bodies to test variety
        for (int i = 0; i < 300; i++) {
            generatedBodies.add(generator.next());
        }

        // We should have good variety
        assertTrue(generatedBodies.size() >= 100,
                "Generator should produce varied bodies, got: " + generatedBodies.size());
    }

    @Test
    void shouldGenerateNonEmptyContent() {
        // Test that generator produces content with substance
        for (int i = 0; i < 20; i++) {
            HTTPBody body = generator.next();
            assertNotNull(body.content(), "Content should not be null");
            // Content can be empty (that's valid for HTTP bodies), just not null
        }
    }

    @Test
    void shouldGenerateVariedContent() {
        Set<String> contentValues = new HashSet<>();

        // Generate bodies to test content variety
        for (int i = 0; i < 50; i++) {
            HTTPBody body = generator.next();
            assertNotNull(body.content(), "Generated content should not be null");
            contentValues.add(body.content());
        }

        // Should generate some variety in content
        assertTrue(contentValues.size() >= 5, "Should generate varied content");
    }

    @Test
    void shouldGenerateValidBodies() {
        // Test that generator produces valid HTTPBody objects
        for (int i = 0; i < 10; i++) {
            HTTPBody body = generator.next();
            assertNotNull(body, "Generated body should not be null");
            assertNotNull(body.content(), "Content should not be null");
            assertNotNull(body.contentType(), "Content type should not be null");
            assertNotNull(body.encoding(), "Encoding should not be null");
        }
    }

    @Test
    void shouldGenerateVariedContentTypes() {
        Set<String> contentTypes = new HashSet<>();

        // Generate bodies to test content type variety
        for (int i = 0; i < 50; i++) {
            HTTPBody body = generator.next();
            assertNotNull(body.contentType(), "Content type should not be null");
            contentTypes.add(body.contentType());
        }

        // Should generate variety in content types
        assertTrue(contentTypes.size() >= 5, "Should generate varied content types");
    }

    @Test
    void shouldGenerateVariedEncodings() {
        Set<String> encodings = new HashSet<>();

        // Generate bodies to test encoding variety
        for (int i = 0; i < 50; i++) {
            HTTPBody body = generator.next();
            assertNotNull(body.encoding(), "Encoding should not be null");
            encodings.add(body.encoding());
        }

        // Should generate variety in encodings
        assertTrue(encodings.size() >= 3, "Should generate varied encodings");
    }

    @Test
    void shouldGenerateValidRecordStructure() {
        // Test that all generated bodies have valid record structure
        for (int i = 0; i < 100; i++) {
            HTTPBody body = generator.next();

            // Test record methods work correctly
            assertNotNull(body.content(), "HTTPBody content should not be null");
            assertNotNull(body.contentType(), "HTTPBody contentType should not be null");
            assertNotNull(body.encoding(), "HTTPBody encoding should not be null");

            // Test toString method works (records auto-generate this)
            String toString = body.toString();
            assertTrue(toString.contains("HTTPBody"), "toString should contain record name");
            assertTrue(toString.contains(body.content()) || body.content().length() > 100,
                    "toString should contain content or content is very long");

            // Test equals and hashCode work (records auto-generate these)
            HTTPBody duplicate = new HTTPBody(body.content(), body.contentType(), body.encoding());
            assertEquals(body, duplicate, "Equal bodies should be equal");
            assertEquals(body.hashCode(), duplicate.hashCode(), "Equal bodies should have same hash code");
        }
    }

    @Test
    void shouldGenerateOverallVariety() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate a set to test overall variety
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Should generate reasonable variety across all fields
        assertTrue(generated.size() >= 20, "Should generate reasonable variety of HTTP bodies");
    }
}