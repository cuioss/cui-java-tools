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
package de.cuioss.http.security.config;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link SecurityDefaults}
 */
class SecurityDefaultsTest {

    @Test
    void shouldHaveCorrectPathLengthConstants() {
        assertEquals(1024, SecurityDefaults.MAX_PATH_LENGTH_STRICT);
        assertEquals(4096, SecurityDefaults.MAX_PATH_LENGTH_DEFAULT);
        assertEquals(8192, SecurityDefaults.MAX_PATH_LENGTH_LENIENT);

        assertTrue(SecurityDefaults.MAX_PATH_LENGTH_STRICT < SecurityDefaults.MAX_PATH_LENGTH_DEFAULT);
        assertTrue(SecurityDefaults.MAX_PATH_LENGTH_DEFAULT < SecurityDefaults.MAX_PATH_LENGTH_LENIENT);
    }

    @Test
    void shouldHaveCorrectParameterCountConstants() {
        assertEquals(20, SecurityDefaults.MAX_PARAMETER_COUNT_STRICT);
        assertEquals(100, SecurityDefaults.MAX_PARAMETER_COUNT_DEFAULT);
        assertEquals(500, SecurityDefaults.MAX_PARAMETER_COUNT_LENIENT);

        assertTrue(SecurityDefaults.MAX_PARAMETER_COUNT_STRICT < SecurityDefaults.MAX_PARAMETER_COUNT_DEFAULT);
        assertTrue(SecurityDefaults.MAX_PARAMETER_COUNT_DEFAULT < SecurityDefaults.MAX_PARAMETER_COUNT_LENIENT);
    }

    @Test
    void shouldHaveCorrectParameterLengthConstants() {
        assertEquals(64, SecurityDefaults.MAX_PARAMETER_NAME_LENGTH_STRICT);
        assertEquals(128, SecurityDefaults.MAX_PARAMETER_NAME_LENGTH_DEFAULT);
        assertEquals(256, SecurityDefaults.MAX_PARAMETER_NAME_LENGTH_LENIENT);

        assertEquals(1024, SecurityDefaults.MAX_PARAMETER_VALUE_LENGTH_STRICT);
        assertEquals(2048, SecurityDefaults.MAX_PARAMETER_VALUE_LENGTH_DEFAULT);
        assertEquals(8192, SecurityDefaults.MAX_PARAMETER_VALUE_LENGTH_LENIENT);
    }

    @Test
    void shouldHaveCorrectHeaderConstants() {
        assertEquals(20, SecurityDefaults.MAX_HEADER_COUNT_STRICT);
        assertEquals(50, SecurityDefaults.MAX_HEADER_COUNT_DEFAULT);
        assertEquals(100, SecurityDefaults.MAX_HEADER_COUNT_LENIENT);

        assertEquals(64, SecurityDefaults.MAX_HEADER_NAME_LENGTH_STRICT);
        assertEquals(128, SecurityDefaults.MAX_HEADER_NAME_LENGTH_DEFAULT);
        assertEquals(256, SecurityDefaults.MAX_HEADER_NAME_LENGTH_LENIENT);

        assertEquals(1024, SecurityDefaults.MAX_HEADER_VALUE_LENGTH_STRICT);
        assertEquals(2048, SecurityDefaults.MAX_HEADER_VALUE_LENGTH_DEFAULT);
        assertEquals(8192, SecurityDefaults.MAX_HEADER_VALUE_LENGTH_LENIENT);
    }

    @Test
    void shouldHaveCorrectCookieConstants() {
        assertEquals(10, SecurityDefaults.MAX_COOKIE_COUNT_STRICT);
        assertEquals(20, SecurityDefaults.MAX_COOKIE_COUNT_DEFAULT);
        assertEquals(50, SecurityDefaults.MAX_COOKIE_COUNT_LENIENT);

        assertEquals(64, SecurityDefaults.MAX_COOKIE_NAME_LENGTH_STRICT);
        assertEquals(128, SecurityDefaults.MAX_COOKIE_NAME_LENGTH_DEFAULT);
        assertEquals(256, SecurityDefaults.MAX_COOKIE_NAME_LENGTH_LENIENT);

        assertEquals(1024, SecurityDefaults.MAX_COOKIE_VALUE_LENGTH_STRICT);
        assertEquals(2048, SecurityDefaults.MAX_COOKIE_VALUE_LENGTH_DEFAULT);
        assertEquals(8192, SecurityDefaults.MAX_COOKIE_VALUE_LENGTH_LENIENT);
    }

    @Test
    void shouldHaveCorrectBodySizeConstants() {
        assertEquals(SecurityDefaults.MAX_BODY_SIZE_STRICT, 1024 * 1024);
        assertEquals(SecurityDefaults.MAX_BODY_SIZE_DEFAULT, 5 * 1024 * 1024);
        assertEquals(SecurityDefaults.MAX_BODY_SIZE_LENIENT, 10 * 1024 * 1024);

        assertTrue(SecurityDefaults.MAX_BODY_SIZE_STRICT < SecurityDefaults.MAX_BODY_SIZE_DEFAULT);
        assertTrue(SecurityDefaults.MAX_BODY_SIZE_DEFAULT < SecurityDefaults.MAX_BODY_SIZE_LENIENT);
    }

    @Test
    void shouldHavePathTraversalPatterns() {
        assertNotNull(SecurityDefaults.PATH_TRAVERSAL_PATTERNS);
        assertFalse(SecurityDefaults.PATH_TRAVERSAL_PATTERNS.isEmpty());

        assertTrue(SecurityDefaults.PATH_TRAVERSAL_PATTERNS.contains("../"));
        assertTrue(SecurityDefaults.PATH_TRAVERSAL_PATTERNS.contains("..\\"));
        assertTrue(SecurityDefaults.PATH_TRAVERSAL_PATTERNS.contains("..%2F"));
        assertTrue(SecurityDefaults.PATH_TRAVERSAL_PATTERNS.contains("%2E%2E/"));
    }

    @Test
    void shouldHaveSuspiciousPathPatterns() {
        assertNotNull(SecurityDefaults.SUSPICIOUS_PATH_PATTERNS);
        assertFalse(SecurityDefaults.SUSPICIOUS_PATH_PATTERNS.isEmpty());

        assertTrue(SecurityDefaults.SUSPICIOUS_PATH_PATTERNS.contains("/etc/"));
        assertTrue(SecurityDefaults.SUSPICIOUS_PATH_PATTERNS.contains("\\windows\\"));
        assertTrue(SecurityDefaults.SUSPICIOUS_PATH_PATTERNS.contains("web.xml"));
        assertTrue(SecurityDefaults.SUSPICIOUS_PATH_PATTERNS.contains(".env"));
    }

    @Test
    void shouldHaveSuspiciousParameterNames() {
        assertNotNull(SecurityDefaults.SUSPICIOUS_PARAMETER_NAMES);
        assertFalse(SecurityDefaults.SUSPICIOUS_PARAMETER_NAMES.isEmpty());

        // Only HTTP-layer appropriate suspicious parameter names
        assertTrue(SecurityDefaults.SUSPICIOUS_PARAMETER_NAMES.contains("script"));
        assertTrue(SecurityDefaults.SUSPICIOUS_PARAMETER_NAMES.contains("include"));
        assertTrue(SecurityDefaults.SUSPICIOUS_PARAMETER_NAMES.contains("file"));
        assertTrue(SecurityDefaults.SUSPICIOUS_PARAMETER_NAMES.contains("path"));
    }

    @Test
    void shouldHaveDangerousHeaderNames() {
        assertNotNull(SecurityDefaults.DANGEROUS_HEADER_NAMES);
        assertFalse(SecurityDefaults.DANGEROUS_HEADER_NAMES.isEmpty());

        assertTrue(SecurityDefaults.DANGEROUS_HEADER_NAMES.contains("X-Debug"));
        assertTrue(SecurityDefaults.DANGEROUS_HEADER_NAMES.contains("X-Admin"));
        assertTrue(SecurityDefaults.DANGEROUS_HEADER_NAMES.contains("X-Execute"));
    }

    @Test
    void shouldHaveDebugHeaderNames() {
        assertNotNull(SecurityDefaults.DEBUG_HEADER_NAMES);
        assertFalse(SecurityDefaults.DEBUG_HEADER_NAMES.isEmpty());

        assertTrue(SecurityDefaults.DEBUG_HEADER_NAMES.contains("X-Debug"));
        assertTrue(SecurityDefaults.DEBUG_HEADER_NAMES.contains("X-Trace"));
        assertTrue(SecurityDefaults.DEBUG_HEADER_NAMES.contains("X-Development"));
    }

    @Test
    void shouldHaveSuspiciousCookieNames() {
        assertNotNull(SecurityDefaults.SUSPICIOUS_COOKIE_NAMES);
        assertFalse(SecurityDefaults.SUSPICIOUS_COOKIE_NAMES.isEmpty());

        assertTrue(SecurityDefaults.SUSPICIOUS_COOKIE_NAMES.contains("debug"));
        assertTrue(SecurityDefaults.SUSPICIOUS_COOKIE_NAMES.contains("admin"));
        assertTrue(SecurityDefaults.SUSPICIOUS_COOKIE_NAMES.contains("password"));
    }

    @Test
    void shouldHaveSafeContentTypes() {
        assertNotNull(SecurityDefaults.SAFE_CONTENT_TYPES);
        assertFalse(SecurityDefaults.SAFE_CONTENT_TYPES.isEmpty());

        assertTrue(SecurityDefaults.SAFE_CONTENT_TYPES.contains("application/json"));
        assertTrue(SecurityDefaults.SAFE_CONTENT_TYPES.contains("text/plain"));
        assertTrue(SecurityDefaults.SAFE_CONTENT_TYPES.contains("application/xml"));
    }

    @Test
    void shouldHaveDangerousContentTypes() {
        assertNotNull(SecurityDefaults.DANGEROUS_CONTENT_TYPES);
        assertFalse(SecurityDefaults.DANGEROUS_CONTENT_TYPES.isEmpty());

        assertTrue(SecurityDefaults.DANGEROUS_CONTENT_TYPES.contains("application/x-executable"));
        assertTrue(SecurityDefaults.DANGEROUS_CONTENT_TYPES.contains("application/x-msdownload"));
        assertTrue(SecurityDefaults.DANGEROUS_CONTENT_TYPES.contains("text/x-script"));
    }

    @Test
    void shouldHaveUploadContentTypes() {
        assertNotNull(SecurityDefaults.UPLOAD_CONTENT_TYPES);
        assertFalse(SecurityDefaults.UPLOAD_CONTENT_TYPES.isEmpty());

        assertTrue(SecurityDefaults.UPLOAD_CONTENT_TYPES.contains("multipart/form-data"));
        assertTrue(SecurityDefaults.UPLOAD_CONTENT_TYPES.contains("image/jpeg"));
        assertTrue(SecurityDefaults.UPLOAD_CONTENT_TYPES.contains("application/pdf"));
    }

    @Test
    void shouldHaveCharacterConstants() {
        assertEquals('\0', SecurityDefaults.NULL_BYTE);

        assertNotNull(SecurityDefaults.PROBLEMATIC_CONTROL_CHARS);
        assertTrue(SecurityDefaults.PROBLEMATIC_CONTROL_CHARS.contains('\0'));
        assertTrue(SecurityDefaults.PROBLEMATIC_CONTROL_CHARS.contains('\b'));

        assertNotNull(SecurityDefaults.INJECTION_CHARACTERS);
        assertTrue(SecurityDefaults.INJECTION_CHARACTERS.contains('<'));
        assertTrue(SecurityDefaults.INJECTION_CHARACTERS.contains('>'));
        assertTrue(SecurityDefaults.INJECTION_CHARACTERS.contains('\''));
    }

    // XSS patterns removed - application layer responsibility.
    // Application layers have proper context for HTML/JS escaping and validation.

    @Test
    void shouldHaveEncodingPatterns() {
        assertNotNull(SecurityDefaults.DOUBLE_ENCODING_PATTERNS);
        assertFalse(SecurityDefaults.DOUBLE_ENCODING_PATTERNS.isEmpty());

        assertTrue(SecurityDefaults.DOUBLE_ENCODING_PATTERNS.contains("%25"));
        assertTrue(SecurityDefaults.DOUBLE_ENCODING_PATTERNS.contains("%2525"));

        assertNotNull(SecurityDefaults.UNICODE_NORMALIZATION_FORMS);
        assertFalse(SecurityDefaults.UNICODE_NORMALIZATION_FORMS.isEmpty());

        assertTrue(SecurityDefaults.UNICODE_NORMALIZATION_FORMS.contains("NFC"));
        assertTrue(SecurityDefaults.UNICODE_NORMALIZATION_FORMS.contains("NFKD"));
    }

    @Test
    void shouldHavePrebuiltConfigurations() {
        assertNotNull(SecurityDefaults.STRICT_CONFIGURATION);
        assertNotNull(SecurityDefaults.DEFAULT_CONFIGURATION);
        assertNotNull(SecurityDefaults.LENIENT_CONFIGURATION);

        assertTrue(SecurityDefaults.STRICT_CONFIGURATION.isStrict());
        assertFalse(SecurityDefaults.DEFAULT_CONFIGURATION.isStrict());
        assertFalse(SecurityDefaults.DEFAULT_CONFIGURATION.isLenient());
        assertTrue(SecurityDefaults.LENIENT_CONFIGURATION.isLenient());
    }

    @Test
    void shouldHaveConsistentStrictConfiguration() {
        SecurityConfiguration strict = SecurityDefaults.STRICT_CONFIGURATION;

        assertEquals(SecurityDefaults.MAX_PATH_LENGTH_STRICT, strict.maxPathLength());
        assertEquals(SecurityDefaults.MAX_PARAMETER_COUNT_STRICT, strict.maxParameterCount());
        assertEquals(SecurityDefaults.MAX_HEADER_COUNT_STRICT, strict.maxHeaderCount());
        assertEquals(SecurityDefaults.MAX_COOKIE_COUNT_STRICT, strict.maxCookieCount());
        assertEquals(SecurityDefaults.MAX_BODY_SIZE_STRICT, strict.maxBodySize());

        assertFalse(strict.allowPathTraversal());
        assertFalse(strict.allowDoubleEncoding());
        assertTrue(strict.requireSecureCookies());
        assertTrue(strict.requireHttpOnlyCookies());
    }

    @Test
    void shouldHaveConsistentDefaultConfiguration() {
        SecurityConfiguration defaults = SecurityDefaults.DEFAULT_CONFIGURATION;

        assertEquals(SecurityDefaults.MAX_PATH_LENGTH_DEFAULT, defaults.maxPathLength());
        assertEquals(SecurityDefaults.MAX_PARAMETER_COUNT_DEFAULT, defaults.maxParameterCount());
        assertEquals(SecurityDefaults.MAX_HEADER_COUNT_DEFAULT, defaults.maxHeaderCount());
        assertEquals(SecurityDefaults.MAX_COOKIE_COUNT_DEFAULT, defaults.maxCookieCount());
        assertEquals(SecurityDefaults.MAX_BODY_SIZE_DEFAULT, defaults.maxBodySize());

        assertFalse(defaults.allowPathTraversal());
        assertFalse(defaults.allowDoubleEncoding());
        assertFalse(defaults.requireSecureCookies());
        assertFalse(defaults.requireHttpOnlyCookies());
    }

    @Test
    void shouldHaveConsistentLenientConfiguration() {
        SecurityConfiguration lenient = SecurityDefaults.LENIENT_CONFIGURATION;

        assertEquals(SecurityDefaults.MAX_PATH_LENGTH_LENIENT, lenient.maxPathLength());
        assertEquals(SecurityDefaults.MAX_PARAMETER_COUNT_LENIENT, lenient.maxParameterCount());
        assertEquals(SecurityDefaults.MAX_HEADER_COUNT_LENIENT, lenient.maxHeaderCount());
        assertEquals(SecurityDefaults.MAX_COOKIE_COUNT_LENIENT, lenient.maxCookieCount());
        assertEquals(SecurityDefaults.MAX_BODY_SIZE_LENIENT, lenient.maxBodySize());

        assertFalse(lenient.allowPathTraversal()); // Still not allowed
        assertTrue(lenient.allowDoubleEncoding());
        assertFalse(lenient.requireSecureCookies());
        assertFalse(lenient.requireHttpOnlyCookies());
    }

    @Test
    void shouldHaveImmutableSets() {
        assertThrows(UnsupportedOperationException.class, () ->
                SecurityDefaults.PATH_TRAVERSAL_PATTERNS.add("test"));

        assertThrows(UnsupportedOperationException.class, () ->
                SecurityDefaults.DANGEROUS_HEADER_NAMES.add("test"));

        assertThrows(UnsupportedOperationException.class, () ->
                SecurityDefaults.SAFE_CONTENT_TYPES.add("test"));
    }

    @Test
    void shouldHaveNonEmptySets() {
        assertTrue(SecurityDefaults.PATH_TRAVERSAL_PATTERNS.size() > 5);
        assertTrue(SecurityDefaults.SUSPICIOUS_PATH_PATTERNS.size() > 5);
        assertTrue(SecurityDefaults.SUSPICIOUS_PARAMETER_NAMES.size() > 5);
        assertTrue(SecurityDefaults.DANGEROUS_HEADER_NAMES.size() > 3);
        assertTrue(SecurityDefaults.SAFE_CONTENT_TYPES.size() > 5);
        assertTrue(SecurityDefaults.DANGEROUS_CONTENT_TYPES.size() > 3);
        assertTrue(SecurityDefaults.PROBLEMATIC_CONTROL_CHARS.size() > 10);
        assertTrue(SecurityDefaults.INJECTION_CHARACTERS.size() > 5);
        // XSS patterns removed - application layer responsibility
    }

    @Test
    void shouldHaveLogicalProgression() {
        assertTrue(SecurityDefaults.MAX_PATH_LENGTH_STRICT < SecurityDefaults.MAX_PATH_LENGTH_DEFAULT);
        assertTrue(SecurityDefaults.MAX_PATH_LENGTH_DEFAULT < SecurityDefaults.MAX_PATH_LENGTH_LENIENT);

        assertTrue(SecurityDefaults.MAX_BODY_SIZE_STRICT < SecurityDefaults.MAX_BODY_SIZE_DEFAULT);
        assertTrue(SecurityDefaults.MAX_BODY_SIZE_DEFAULT < SecurityDefaults.MAX_BODY_SIZE_LENIENT);

        assertTrue(SecurityDefaults.MAX_PARAMETER_COUNT_STRICT < SecurityDefaults.MAX_PARAMETER_COUNT_DEFAULT);
        assertTrue(SecurityDefaults.MAX_PARAMETER_COUNT_DEFAULT < SecurityDefaults.MAX_PARAMETER_COUNT_LENIENT);
    }
}