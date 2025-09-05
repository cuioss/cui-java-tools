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
    void shouldGenerateSafeContent() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test safe content
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for safe content patterns
        boolean hasJsonContent = generated.stream().anyMatch(b -> b.content().contains("{\"user\""));
        boolean hasFormContent = generated.stream().anyMatch(b -> b.content().contains("username="));
        boolean hasXmlContent = generated.stream().anyMatch(b -> b.content().contains("<user>"));
        boolean hasTextContent = generated.stream().anyMatch(b -> "Hello World".equals(b.content()));

        assertTrue(hasJsonContent, "Should generate JSON content");
        assertTrue(hasFormContent, "Should generate form-encoded content");
        assertTrue(hasXmlContent, "Should generate XML content");
        assertTrue(hasTextContent, "Should generate plain text content");
    }

    @Test
    void shouldGenerateAttackContent() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test attack content
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for attack patterns
        boolean hasXssAttack = generated.stream().anyMatch(b -> b.content().contains("<script>"));
        boolean hasSqlInjection = generated.stream().anyMatch(b -> b.content().contains("DROP TABLE"));
        boolean hasPathTraversal = generated.stream().anyMatch(b -> b.content().contains("../../../"));
        boolean hasJndiAttack = generated.stream().anyMatch(b -> b.content().contains("${jndi:"));
        boolean hasXxeAttack = generated.stream().anyMatch(b -> b.content().contains("<!ENTITY xxe"));

        assertTrue(hasXssAttack, "Should generate XSS attack content");
        assertTrue(hasSqlInjection, "Should generate SQL injection attack content");
        assertTrue(hasPathTraversal, "Should generate path traversal attack content");
        assertTrue(hasJndiAttack, "Should generate JNDI attack content");
        assertTrue(hasXxeAttack, "Should generate XXE attack content");
    }

    @Test
    void shouldGenerateMalformedContent() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test malformed content
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for malformed patterns
        boolean hasEmptyContent = generated.stream().anyMatch(b -> b.content().isEmpty());
        boolean hasWhitespaceContent = generated.stream().anyMatch(b -> b.content().trim().isEmpty() && !b.content().isEmpty());
        boolean hasMalformedJson = generated.stream().anyMatch(b -> b.content().contains("{\"malformed\": json,}"));
        boolean hasMalformedXml = generated.stream().anyMatch(b -> b.content().contains("<unclosed><tag>"));

        assertTrue(hasEmptyContent, "Should generate empty content");
        assertTrue(hasWhitespaceContent, "Should generate whitespace-only content");
        assertTrue(hasMalformedJson, "Should generate malformed JSON");
        assertTrue(hasMalformedXml, "Should generate malformed XML");
    }

    @Test
    void shouldGenerateStandardContentTypes() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test content types
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for standard content types
        boolean hasJsonType = generated.stream().anyMatch(b -> "application/json".equals(b.contentType()));
        boolean hasFormType = generated.stream().anyMatch(b -> "application/x-www-form-urlencoded".equals(b.contentType()));
        boolean hasHtmlType = generated.stream().anyMatch(b -> "text/html".equals(b.contentType()));
        boolean hasXmlType = generated.stream().anyMatch(b -> "application/xml".equals(b.contentType()));
        boolean hasMultipartType = generated.stream().anyMatch(b -> "multipart/form-data".equals(b.contentType()));

        assertTrue(hasJsonType, "Should generate JSON content type");
        assertTrue(hasFormType, "Should generate form content type");
        assertTrue(hasHtmlType, "Should generate HTML content type");
        assertTrue(hasXmlType, "Should generate XML content type");
        assertTrue(hasMultipartType, "Should generate multipart content type");
    }

    @Test
    void shouldGenerateAttackContentTypes() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test attack content types
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for attack patterns in content types
        boolean hasScriptInType = generated.stream().anyMatch(b -> b.contentType().contains("<script>"));
        boolean hasHeaderInjection = generated.stream().anyMatch(b -> b.contentType().contains("\r\n"));
        boolean hasPathTraversal = generated.stream().anyMatch(b -> "../../../etc/passwd".equals(b.contentType()));
        boolean hasEmptyType = generated.stream().anyMatch(b -> b.contentType().isEmpty());
        boolean hasWhitespaceType = generated.stream().anyMatch(b -> b.contentType().trim().isEmpty() && !b.contentType().isEmpty());

        assertTrue(hasScriptInType, "Should generate script injection in content type");
        assertTrue(hasHeaderInjection, "Should generate header injection in content type");
        assertTrue(hasPathTraversal, "Should generate path traversal in content type");
        assertTrue(hasEmptyType, "Should generate empty content type");
        assertTrue(hasWhitespaceType, "Should generate whitespace content type");
    }

    @Test
    void shouldGenerateStandardEncodings() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test encodings
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for standard encodings
        boolean hasNoEncoding = generated.stream().anyMatch(b -> b.encoding().isEmpty());
        boolean hasGzipEncoding = generated.stream().anyMatch(b -> "gzip".equals(b.encoding()));
        boolean hasDeflateEncoding = generated.stream().anyMatch(b -> "deflate".equals(b.encoding()));
        boolean hasBrotliEncoding = generated.stream().anyMatch(b -> "br".equals(b.encoding()));
        boolean hasMultipleEncodings = generated.stream().anyMatch(b -> "gzip, deflate".equals(b.encoding()));

        assertTrue(hasNoEncoding, "Should generate no encoding");
        assertTrue(hasGzipEncoding, "Should generate gzip encoding");
        assertTrue(hasDeflateEncoding, "Should generate deflate encoding");
        assertTrue(hasBrotliEncoding, "Should generate brotli encoding");
        assertTrue(hasMultipleEncodings, "Should generate multiple encodings");
    }

    @Test
    void shouldGenerateAttackEncodings() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test attack encodings
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for attack patterns in encodings
        boolean hasPathTraversalEncoding = generated.stream().anyMatch(b -> "../../../etc/passwd".equals(b.encoding()));
        boolean hasScriptEncoding = generated.stream().anyMatch(b -> b.encoding().contains("<script>"));
        boolean hasHeaderInjection = generated.stream().anyMatch(b -> b.encoding().contains("\r\n"));
        boolean hasNullByteEncoding = generated.stream().anyMatch(b -> b.encoding().contains("\\u0000"));

        assertTrue(hasPathTraversalEncoding, "Should generate path traversal in encoding");
        assertTrue(hasScriptEncoding, "Should generate script injection in encoding");
        assertTrue(hasHeaderInjection, "Should generate header injection in encoding");
        assertTrue(hasNullByteEncoding, "Should generate null bytes in encoding");
    }

    @Test
    void shouldGenerateHttpResponseSplitting() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test HTTP response splitting
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for HTTP response splitting patterns
        boolean hasResponseSplittingContent = generated.stream().anyMatch(b ->
                b.content().contains("HTTP/1.1 200 OK"));
        boolean hasResponseSplittingType = generated.stream().anyMatch(b ->
                b.contentType().contains("HTTP/1.1"));
        boolean hasResponseSplittingEncoding = generated.stream().anyMatch(b ->
                b.encoding().contains("HTTP/1.1"));

        assertTrue(hasResponseSplittingContent, "Should generate response splitting in content");
        assertTrue(hasResponseSplittingType, "Should generate response splitting in content type");
        assertTrue(hasResponseSplittingEncoding, "Should generate response splitting in encoding");
    }

    @Test
    void shouldGenerateLargePayloads() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test large payloads
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for large payloads
        boolean hasLargeContent = generated.stream().anyMatch(b -> b.content().length() > 10000);
        boolean hasLongEncoding = generated.stream().anyMatch(b -> b.encoding().length() > 100);

        assertTrue(hasLargeContent, "Should generate large content payloads");
        assertTrue(hasLongEncoding, "Should generate long encoding values");
    }

    @Test
    void shouldGenerateUnicodeAttacks() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate bodies to test Unicode attacks
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for Unicode-based attacks
        boolean hasDirectionOverrideContent = generated.stream().anyMatch(b -> b.content().contains("\u202e"));
        boolean hasDirectionOverrideType = generated.stream().anyMatch(b -> b.contentType().contains("\u202e"));
        boolean hasZeroWidthChars = generated.stream().anyMatch(b -> b.content().contains("\u200B"));
        boolean hasBomInContent = generated.stream().anyMatch(b -> b.content().contains("\uFEFF"));

        assertTrue(hasDirectionOverrideContent, "Should generate Unicode direction override in content");
        assertTrue(hasDirectionOverrideType, "Should generate Unicode direction override in content type");
        assertTrue(hasZeroWidthChars, "Should generate zero-width characters");
        assertTrue(hasBomInContent, "Should generate BOM in content");
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
    void shouldGenerateReasonableVariety() {
        Set<HTTPBody> generated = new HashSet<>();

        // Generate a large set to test overall variety
        for (int i = 0; i < 500; i++) {
            generated.add(generator.next());
        }

        // Should have bodies from different categories
        boolean hasSafeContent = generated.stream().anyMatch(b ->
                b.content().contains("Hello World") || b.content().contains("{\"user\""));
        boolean hasAttackContent = generated.stream().anyMatch(b ->
                b.content().contains("<script>") || b.content().contains("DROP TABLE"));
        boolean hasStandardTypes = generated.stream().anyMatch(b ->
                "application/json".equals(b.contentType()) || "text/html".equals(b.contentType()));
        boolean hasAttackTypes = generated.stream().anyMatch(b ->
                b.contentType().contains("<script>") || b.contentType().isEmpty());

        assertTrue(hasSafeContent, "Should generate safe content");
        assertTrue(hasAttackContent, "Should generate attack content");
        assertTrue(hasStandardTypes, "Should generate standard content types");
        assertTrue(hasAttackTypes, "Should generate attack content types");

        // Should generate reasonable variety
        assertTrue(generated.size() >= 150, "Should generate reasonable variety of HTTP bodies");
    }
}