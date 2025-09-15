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

import de.cuioss.test.generator.Generators;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link HTTPBody}
 */
class HTTPBodyTest {

    private static final String JSON_CONTENT = "{\"userId\": 123, \"name\": \"John\"}";
    private static final String HTML_CONTENT = "<html><body>Hello World</body></html>";
    private static final String FORM_CONTENT = "username=admin&password=secret";
    private static final String TEXT_CONTENT = "Simple text content";

    @Test
    void shouldCreateBodyWithContentTypeAndEncoding() {
        HTTPBody body = new HTTPBody(JSON_CONTENT, "application/json", "gzip");

        assertEquals(JSON_CONTENT, body.content());
        assertEquals("application/json", body.contentType());
        assertEquals("gzip", body.encoding());
    }

    @Test
    void shouldCreateBodyWithNullValues() {
        HTTPBody body1 = new HTTPBody(null, "application/json", "gzip");
        HTTPBody body2 = new HTTPBody(JSON_CONTENT, null, "gzip");
        HTTPBody body3 = new HTTPBody(JSON_CONTENT, "application/json", null);
        HTTPBody body4 = new HTTPBody(null, null, null);

        assertNull(body1.content());
        assertEquals("application/json", body1.contentType());
        assertEquals("gzip", body1.encoding());

        assertEquals(JSON_CONTENT, body2.content());
        assertNull(body2.contentType());
        assertEquals("gzip", body2.encoding());

        assertEquals(JSON_CONTENT, body3.content());
        assertEquals("application/json", body3.contentType());
        assertNull(body3.encoding());

        assertNull(body4.content());
        assertNull(body4.contentType());
        assertNull(body4.encoding());
    }

    @Test
    void shouldCreateBodyWithFactoryMethods() {
        HTTPBody textBody = HTTPBody.text(TEXT_CONTENT);
        HTTPBody jsonBody = HTTPBody.json(JSON_CONTENT);
        HTTPBody htmlBody = HTTPBody.html(HTML_CONTENT);
        HTTPBody formBody = HTTPBody.form(FORM_CONTENT);
        HTTPBody customBody = HTTPBody.of("content", "custom/type");

        assertEquals(TEXT_CONTENT, textBody.content());
        assertEquals("text/plain", textBody.contentType());
        assertEquals("", textBody.encoding());

        assertEquals(JSON_CONTENT, jsonBody.content());
        assertEquals("application/json", jsonBody.contentType());
        assertEquals("", jsonBody.encoding());

        assertEquals(HTML_CONTENT, htmlBody.content());
        assertEquals("text/html", htmlBody.contentType());
        assertEquals("", htmlBody.encoding());

        assertEquals(FORM_CONTENT, formBody.content());
        assertEquals("application/x-www-form-urlencoded", formBody.contentType());
        assertEquals("", formBody.encoding());

        assertEquals("content", customBody.content());
        assertEquals("custom/type", customBody.contentType());
        assertEquals("", customBody.encoding());
    }

    @Test
    void shouldDetectBodyWithContent() {
        HTTPBody withContent = new HTTPBody(JSON_CONTENT, "application/json", "");
        HTTPBody withoutContent = new HTTPBody(null, "application/json", "");
        HTTPBody withEmptyContent = new HTTPBody("", "application/json", "");

        assertTrue(withContent.hasContent());
        assertFalse(withoutContent.hasContent());
        assertFalse(withEmptyContent.hasContent());
    }

    @Test
    void shouldDetectBodyWithContentType() {
        HTTPBody withContentType = new HTTPBody(JSON_CONTENT, "application/json", "");
        HTTPBody withoutContentType = new HTTPBody(JSON_CONTENT, null, "");
        HTTPBody withEmptyContentType = new HTTPBody(JSON_CONTENT, "", "");

        assertTrue(withContentType.hasContentType());
        assertFalse(withoutContentType.hasContentType());
        assertFalse(withEmptyContentType.hasContentType());
    }

    @Test
    void shouldDetectBodyWithEncoding() {
        HTTPBody withEncoding = new HTTPBody(JSON_CONTENT, "application/json", "gzip");
        HTTPBody withoutEncoding = new HTTPBody(JSON_CONTENT, "application/json", null);
        HTTPBody withEmptyEncoding = new HTTPBody(JSON_CONTENT, "application/json", "");

        assertTrue(withEncoding.hasEncoding());
        assertFalse(withoutEncoding.hasEncoding());
        assertFalse(withEmptyEncoding.hasEncoding());
    }

    @Test
    void shouldDetectCompressedContent() {
        HTTPBody compressed = new HTTPBody(JSON_CONTENT, "application/json", "gzip");
        HTTPBody notCompressed = new HTTPBody(JSON_CONTENT, "application/json", "");

        assertTrue(compressed.isCompressed());
        assertFalse(notCompressed.isCompressed());
    }

    @Test
    void shouldDetectJsonContent() {
        HTTPBody jsonBody1 = new HTTPBody(JSON_CONTENT, "application/json", "");
        HTTPBody jsonBody2 = new HTTPBody(JSON_CONTENT, "application/vnd.api+json", "");
        HTTPBody jsonBody3 = new HTTPBody(JSON_CONTENT, "APPLICATION/JSON", ""); // Case insensitive
        HTTPBody nonJsonBody = new HTTPBody(HTML_CONTENT, "text/html", "");

        assertTrue(jsonBody1.isJson());
        assertTrue(jsonBody2.isJson());
        assertTrue(jsonBody3.isJson());
        assertFalse(nonJsonBody.isJson());
    }

    @Test
    void shouldDetectXmlContent() {
        HTTPBody xmlBody1 = new HTTPBody("<xml/>", "application/xml", "");
        HTTPBody xmlBody2 = new HTTPBody("<xml/>", "text/xml", "");
        HTTPBody xmlBody3 = new HTTPBody("<xml/>", "APPLICATION/XML", ""); // Case insensitive
        HTTPBody nonXmlBody = new HTTPBody(JSON_CONTENT, "application/json", "");

        assertTrue(xmlBody1.isXml());
        assertTrue(xmlBody2.isXml());
        assertTrue(xmlBody3.isXml());
        assertFalse(nonXmlBody.isXml());
    }

    @Test
    void shouldDetectHtmlContent() {
        HTTPBody htmlBody1 = new HTTPBody(HTML_CONTENT, "text/html", "");
        HTTPBody htmlBody2 = new HTTPBody(HTML_CONTENT, "TEXT/HTML", ""); // Case insensitive
        HTTPBody nonHtmlBody = new HTTPBody(JSON_CONTENT, "application/json", "");

        assertTrue(htmlBody1.isHtml());
        assertTrue(htmlBody2.isHtml());
        assertFalse(nonHtmlBody.isHtml());
    }

    @Test
    void shouldDetectPlainTextContent() {
        HTTPBody textBody1 = new HTTPBody(TEXT_CONTENT, "text/plain", "");
        HTTPBody textBody2 = new HTTPBody(TEXT_CONTENT, "TEXT/PLAIN", ""); // Case insensitive
        HTTPBody nonTextBody = new HTTPBody(JSON_CONTENT, "application/json", "");

        assertTrue(textBody1.isPlainText());
        assertTrue(textBody2.isPlainText());
        assertFalse(nonTextBody.isPlainText());
    }

    @Test
    void shouldDetectFormData() {
        HTTPBody formBody1 = new HTTPBody(FORM_CONTENT, "application/x-www-form-urlencoded", "");
        HTTPBody formBody2 = new HTTPBody("", "multipart/form-data", "");
        HTTPBody formBody3 = new HTTPBody("", "APPLICATION/X-WWW-FORM-URLENCODED", ""); // Case insensitive
        HTTPBody nonFormBody = new HTTPBody(JSON_CONTENT, "application/json", "");

        assertTrue(formBody1.isFormData());
        assertTrue(formBody2.isFormData());
        assertTrue(formBody3.isFormData());
        assertFalse(nonFormBody.isFormData());
    }

    @Test
    void shouldDetectBinaryContent() {
        HTTPBody binaryBody1 = new HTTPBody("", "application/octet-stream", "");
        HTTPBody binaryBody2 = new HTTPBody("", "image/png", "");
        HTTPBody binaryBody3 = new HTTPBody("", "video/mp4", "");
        HTTPBody binaryBody4 = new HTTPBody("", "audio/wav", "");
        HTTPBody binaryBody5 = new HTTPBody("", "IMAGE/JPEG", ""); // Case insensitive
        HTTPBody nonBinaryBody = new HTTPBody(JSON_CONTENT, "application/json", "");

        assertTrue(binaryBody1.isBinary());
        assertTrue(binaryBody2.isBinary());
        assertTrue(binaryBody3.isBinary());
        assertTrue(binaryBody4.isBinary());
        assertTrue(binaryBody5.isBinary());
        assertFalse(nonBinaryBody.isBinary());
    }

    @Test
    void shouldCalculateContentLength() {
        HTTPBody withContent = new HTTPBody("hello", "text/plain", "");
        HTTPBody withoutContent = new HTTPBody(null, "text/plain", "");
        HTTPBody emptyContent = new HTTPBody("", "text/plain", "");

        assertEquals(5, withContent.contentLength());
        assertEquals(0, withoutContent.contentLength());
        assertEquals(0, emptyContent.contentLength());
    }

    @Test
    void shouldExtractCharset() {
        HTTPBody bodyWithCharset = new HTTPBody("content", "text/html; charset=utf-8", "");
        HTTPBody bodyWithCharsetUpper = new HTTPBody("content", "text/html; CHARSET=ISO-8859-1", "");
        HTTPBody bodyWithoutCharset = new HTTPBody("content", "text/html", "");
        HTTPBody bodyWithNullContentType = new HTTPBody("content", null, "");

        assertEquals("utf-8", bodyWithCharset.getCharset().orElse(null));
        assertEquals("ISO-8859-1", bodyWithCharsetUpper.getCharset().orElse(null));
        assertTrue(bodyWithoutCharset.getCharset().isEmpty());
        assertTrue(bodyWithNullContentType.getCharset().isEmpty());
    }

    @Test
    void shouldExtractCharsetWithComplexContentType() {
        HTTPBody body1 = new HTTPBody("content", "application/json; charset=utf-8; boundary=something", "");
        HTTPBody body2 = new HTTPBody("content", "text/html; charset=windows-1252;", "");
        HTTPBody body3 = new HTTPBody("content", "application/xml;charset=utf-16", ""); // No space

        assertEquals("utf-8", body1.getCharset().orElse(null));
        assertEquals("windows-1252", body2.getCharset().orElse(null));
        assertEquals("utf-16", body3.getCharset().orElse(null));
    }

    @Test
    void shouldReturnContentOrDefault() {
        HTTPBody withContent = new HTTPBody(JSON_CONTENT, "application/json", "");
        HTTPBody withoutContent = new HTTPBody(null, "application/json", "");

        assertEquals(JSON_CONTENT, withContent.contentOrDefault("default"));
        assertEquals("default", withoutContent.contentOrDefault("default"));
    }

    @Test
    void shouldReturnContentTypeOrDefault() {
        HTTPBody withContentType = new HTTPBody(JSON_CONTENT, "application/json", "");
        HTTPBody withoutContentType = new HTTPBody(JSON_CONTENT, null, "");

        assertEquals("application/json", withContentType.contentTypeOrDefault("default"));
        assertEquals("default", withoutContentType.contentTypeOrDefault("default"));
    }

    @Test
    void shouldReturnEncodingOrDefault() {
        HTTPBody withEncoding = new HTTPBody(JSON_CONTENT, "application/json", "gzip");
        HTTPBody withoutEncoding = new HTTPBody(JSON_CONTENT, "application/json", null);

        assertEquals("gzip", withEncoding.encodingOrDefault("default"));
        assertEquals("default", withoutEncoding.encodingOrDefault("default"));
    }

    @Test
    void shouldCreateBodyWithNewContent() {
        HTTPBody original = new HTTPBody(JSON_CONTENT, "application/json", "gzip");
        HTTPBody newContent = original.withContent("new content");

        assertEquals("new content", newContent.content());
        assertEquals("application/json", newContent.contentType());
        assertEquals("gzip", newContent.encoding());
        assertEquals(JSON_CONTENT, original.content()); // Original unchanged
    }

    @Test
    void shouldCreateBodyWithNewContentType() {
        HTTPBody original = new HTTPBody(JSON_CONTENT, "application/json", "gzip");
        HTTPBody newContentType = original.withContentType("text/plain");

        assertEquals(JSON_CONTENT, newContentType.content());
        assertEquals("text/plain", newContentType.contentType());
        assertEquals("gzip", newContentType.encoding());
        assertEquals("application/json", original.contentType()); // Original unchanged
    }

    @Test
    void shouldCreateBodyWithNewEncoding() {
        HTTPBody original = new HTTPBody(JSON_CONTENT, "application/json", "gzip");
        HTTPBody newEncoding = original.withEncoding("deflate");

        assertEquals(JSON_CONTENT, newEncoding.content());
        assertEquals("application/json", newEncoding.contentType());
        assertEquals("deflate", newEncoding.encoding());
        assertEquals("gzip", original.encoding()); // Original unchanged
    }

    @Test
    void shouldTruncateContent() {
        HTTPBody longContent = new HTTPBody("Hello World", "text/plain", "");
        HTTPBody shortContent = new HTTPBody("Hi", "text/plain", "");
        HTTPBody nullContent = new HTTPBody(null, "text/plain", "");

        assertEquals("Hello...", longContent.contentTruncated(5));
        assertEquals("Hi", shortContent.contentTruncated(5));
        assertEquals("null", nullContent.contentTruncated(5));
        assertEquals("Hello World", longContent.contentTruncated(20)); // No truncation needed
    }

    @Test
    void shouldSupportEquality() {
        HTTPBody body1 = new HTTPBody(JSON_CONTENT, "application/json", "gzip");
        HTTPBody body2 = new HTTPBody(JSON_CONTENT, "application/json", "gzip");
        HTTPBody body3 = new HTTPBody("other", "application/json", "gzip");

        assertEquals(body1, body2);
        assertNotEquals(body1, body3);
        assertEquals(body1.hashCode(), body2.hashCode());
    }

    @Test
    void shouldSupportToString() {
        HTTPBody body = new HTTPBody(JSON_CONTENT, "application/json", "gzip");
        String string = body.toString();

        assertTrue(string.contains(JSON_CONTENT));
        assertTrue(string.contains("application/json"));
        assertTrue(string.contains("gzip"));
    }

    @Test
    void shouldHandleEmptyStrings() {
        HTTPBody body = new HTTPBody("", "", "");

        assertFalse(body.hasContent());
        assertFalse(body.hasContentType());
        assertFalse(body.hasEncoding());
        assertFalse(body.isCompressed());
        assertEquals(0, body.contentLength());
    }

    @Test
    void shouldAcceptAnyContentTypes() {
        // Records are pure data holders - validation is done by consumers
        HTTPBody body1 = new HTTPBody("content", "invalid-mime-type", "");
        assertEquals("invalid-mime-type", body1.contentType());

        HTTPBody body2 = new HTTPBody("content", "application/", "");
        assertEquals("application/", body2.contentType());

        HTTPBody body3 = new HTTPBody("content", "/json", "");
        assertEquals("/json", body3.contentType());
    }

    @Test
    void shouldAcceptAnyEncodings() {
        // Records are pure data holders - validation is done by consumers
        HTTPBody body = new HTTPBody("content", "text/plain", "invalid-encoding");
        assertEquals("invalid-encoding", body.encoding());
    }

    @Test
    void shouldAcceptValidContentTypes() {
        // Valid MIME types should work
        HTTPBody body1 = new HTTPBody("content", "text/plain", "");
        HTTPBody body2 = new HTTPBody("content", "application/json", "");
        HTTPBody body3 = new HTTPBody("content", "text/html; charset=utf-8", "");
        HTTPBody body4 = new HTTPBody("content", "application/vnd.api+json", "");

        assertEquals("text/plain", body1.contentType());
        assertEquals("application/json", body2.contentType());
        assertEquals("text/html; charset=utf-8", body3.contentType());
        assertEquals("application/vnd.api+json", body4.contentType());
    }

    @Test
    void shouldAcceptValidEncodings() {
        // Valid encodings should work
        HTTPBody body1 = new HTTPBody("content", "text/plain", "gzip");
        HTTPBody body2 = new HTTPBody("content", "text/plain", "deflate");
        HTTPBody body3 = new HTTPBody("content", "text/plain", "br");
        HTTPBody body4 = new HTTPBody("content", "text/plain", "identity");

        assertEquals("gzip", body1.encoding());
        assertEquals("deflate", body2.encoding());
        assertEquals("br", body3.encoding());
        assertEquals("identity", body4.encoding());
    }

    @Test
    void shouldBeImmutable() {
        HTTPBody original = new HTTPBody(JSON_CONTENT, "application/json", "gzip");

        HTTPBody withNewContent = original.withContent("new");
        HTTPBody withNewContentType = original.withContentType("text/plain");
        HTTPBody withNewEncoding = original.withEncoding("deflate");

        // Original should be unchanged
        assertEquals(JSON_CONTENT, original.content());
        assertEquals("application/json", original.contentType());
        assertEquals("gzip", original.encoding());

        // New instances should have changes
        assertEquals("new", withNewContent.content());
        assertEquals("text/plain", withNewContentType.contentType());
        assertEquals("deflate", withNewEncoding.encoding());
    }

    @Test
    void shouldHandleLargeContent() {
        // QI-17: Replace 1MB hardcoded pattern with realistic large content
        String largeContent = Generators.letterStrings(800000, 1000000).next(); // Variable large content
        HTTPBody body = new HTTPBody(largeContent, "text/plain", "");

        assertTrue(body.hasContent());
        assertEquals(largeContent.length(), body.contentLength());
        assertTrue(body.contentTruncated(100).endsWith("..."));
        assertEquals(103, body.contentTruncated(100).length()); // 100 chars + "..."
    }

    @Test
    void shouldHandleSpecialCharacters() {
        String specialContent = "Special chars: !@#$%^&*()[]{}|;':\",./<>?";
        HTTPBody body = new HTTPBody(specialContent, "text/plain; charset=utf-8", "br");

        assertEquals(specialContent, body.content());
        assertEquals("utf-8", body.getCharset().orElse(null));
        assertTrue(body.isCompressed());
    }

    @Test
    void shouldHandleUnicodeContent() {
        String unicodeContent = "Unicode: 日本語 français русский عربي";
        HTTPBody body = new HTTPBody(unicodeContent, "text/plain; charset=utf-8", "");

        assertEquals(unicodeContent, body.content());
        assertTrue(body.hasContent());
        assertEquals("utf-8", body.getCharset().orElse(null));
    }
}