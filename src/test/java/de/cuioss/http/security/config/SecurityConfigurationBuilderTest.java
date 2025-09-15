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
 * Test for {@link SecurityConfigurationBuilder}
 */
class SecurityConfigurationBuilderTest {

    @Test
    void shouldCreateBuilderWithDefaults() {
        SecurityConfiguration config = SecurityConfiguration.builder().build();

        assertEquals(4096, config.maxPathLength());
        assertFalse(config.allowPathTraversal());
        assertFalse(config.allowDoubleEncoding());
        assertEquals(100, config.maxParameterCount());
        assertEquals(128, config.maxParameterNameLength());
        assertEquals(2048, config.maxParameterValueLength());
        assertEquals(50, config.maxHeaderCount());
        assertEquals(128, config.maxHeaderNameLength());
        assertEquals(2048, config.maxHeaderValueLength());
        assertNull(config.allowedHeaderNames());
        assertTrue(config.blockedHeaderNames().isEmpty());
        assertEquals(20, config.maxCookieCount());
        assertEquals(128, config.maxCookieNameLength());
        assertEquals(2048, config.maxCookieValueLength());
        assertFalse(config.requireSecureCookies());
        assertFalse(config.requireHttpOnlyCookies());
        assertEquals(5 * 1024 * 1024, config.maxBodySize());
        assertNull(config.allowedContentTypes());
        assertTrue(config.blockedContentTypes().isEmpty());
        assertFalse(config.allowNullBytes());
        assertFalse(config.allowControlCharacters());
        assertTrue(config.allowHighBitCharacters());
        assertFalse(config.normalizeUnicode());
        assertFalse(config.caseSensitiveComparison());
        assertFalse(config.failOnSuspiciousPatterns());
        assertTrue(config.logSecurityViolations());
    }

    @Test
    void shouldSetPathSecuritySettings() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxPathLength(2048)
                .allowPathTraversal(true)
                .allowDoubleEncoding(true)
                .build();

        assertEquals(2048, config.maxPathLength());
        assertTrue(config.allowPathTraversal());
        assertTrue(config.allowDoubleEncoding());
    }

    @Test
    void shouldSetPathSecurityInOneCall() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .pathSecurity(1024, true)
                .build();

        assertEquals(1024, config.maxPathLength());
        assertTrue(config.allowPathTraversal());
    }

    @Test
    void shouldValidatePathLengthPositive() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxPathLength(0));
        assertTrue(thrown.getMessage().contains("maxPathLength must be positive"));

        IllegalArgumentException thrown2 = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxPathLength(-1));
        assertTrue(thrown2.getMessage().contains("maxPathLength must be positive"));
    }

    @Test
    void shouldSetParameterSecuritySettings() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterCount(50)
                .maxParameterNameLength(64)
                .maxParameterValueLength(1024)
                .build();

        assertEquals(50, config.maxParameterCount());
        assertEquals(64, config.maxParameterNameLength());
        assertEquals(1024, config.maxParameterValueLength());
    }

    @Test
    void shouldSetParameterSecurityInOneCall() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .parameterSecurity(30, 32, 512)
                .build();

        assertEquals(30, config.maxParameterCount());
        assertEquals(32, config.maxParameterNameLength());
        assertEquals(512, config.maxParameterValueLength());
    }

    @Test
    void shouldValidateParameterConstraints() {
        // Parameter count can be 0
        SecurityConfiguration.builder().maxParameterCount(0);

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxParameterCount(-1));
        assertTrue(thrown.getMessage().contains("maxParameterCount must be non-negative"));

        IllegalArgumentException thrown2 = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxParameterNameLength(0));
        assertTrue(thrown2.getMessage().contains("maxParameterNameLength must be positive"));

        IllegalArgumentException thrown3 = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxParameterValueLength(0));
        assertTrue(thrown3.getMessage().contains("maxParameterValueLength must be positive"));
    }

    @Test
    void shouldSetHeaderSecuritySettings() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxHeaderCount(30)
                .maxHeaderNameLength(64)
                .maxHeaderValueLength(1024)
                .build();

        assertEquals(30, config.maxHeaderCount());
        assertEquals(64, config.maxHeaderNameLength());
        assertEquals(1024, config.maxHeaderValueLength());
    }

    @Test
    void shouldSetHeaderSecurityInOneCall() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .headerSecurity(25, 32, 512)
                .build();

        assertEquals(25, config.maxHeaderCount());
        assertEquals(32, config.maxHeaderNameLength());
        assertEquals(512, config.maxHeaderValueLength());
    }

    @Test
    void shouldManageAllowedHeaderNames() {
        SecurityConfigurationBuilder builder = SecurityConfiguration.builder();

        SecurityConfiguration config = builder
                .addAllowedHeaderName("Authorization")
                .addAllowedHeaderName("Content-Type")
                .build();

        assertNotNull(config.allowedHeaderNames());
        assertEquals(2, config.allowedHeaderNames().size());
        assertTrue(config.allowedHeaderNames().contains("Authorization"));
        assertTrue(config.allowedHeaderNames().contains("Content-Type"));
    }

    @Test
    void shouldSetAllowedHeaderNamesAsSet() {
        Set<String> headers = Set.of("X-Custom", "Authorization");
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowedHeaderNames(headers)
                .build();

        assertEquals(2, config.allowedHeaderNames().size());
        assertTrue(config.allowedHeaderNames().contains("X-Custom"));
        assertTrue(config.allowedHeaderNames().contains("Authorization"));
    }

    @Test
    void shouldManageBlockedHeaderNames() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .addBlockedHeaderName("X-Debug")
                .addBlockedHeaderName("X-Internal")
                .build();

        assertEquals(2, config.blockedHeaderNames().size());
        assertTrue(config.blockedHeaderNames().contains("X-Debug"));
        assertTrue(config.blockedHeaderNames().contains("X-Internal"));
    }

    @Test
    void shouldSetBlockedHeaderNamesAsSet() {
        Set<String> headers = Set.of("X-Test", "X-Debug");
        SecurityConfiguration config = SecurityConfiguration.builder()
                .blockedHeaderNames(headers)
                .build();

        assertEquals(2, config.blockedHeaderNames().size());
        assertTrue(config.blockedHeaderNames().contains("X-Test"));
        assertTrue(config.blockedHeaderNames().contains("X-Debug"));
    }

    @Test
    void shouldValidateHeaderConstraints() {
        // Header count can be 0
        SecurityConfiguration.builder().maxHeaderCount(0);

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxHeaderCount(-1));
        assertTrue(thrown.getMessage().contains("maxHeaderCount must be non-negative"));

        IllegalArgumentException thrown2 = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxHeaderNameLength(0));
        assertTrue(thrown2.getMessage().contains("maxHeaderNameLength must be positive"));

        IllegalArgumentException thrown3 = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxHeaderValueLength(0));
        assertTrue(thrown3.getMessage().contains("maxHeaderValueLength must be positive"));
    }

    @Test
    void shouldRejectNullHeaderNames() {
        assertThrows(NullPointerException.class, () ->
                SecurityConfiguration.builder().addAllowedHeaderName(null));

        assertThrows(NullPointerException.class, () ->
                SecurityConfiguration.builder().addBlockedHeaderName(null));

        assertThrows(NullPointerException.class, () ->
                SecurityConfiguration.builder().blockedHeaderNames(null));
    }

    @Test
    void shouldSetCookieSecuritySettings() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxCookieCount(15)
                .maxCookieNameLength(64)
                .maxCookieValueLength(1024)
                .requireSecureCookies(true)
                .requireHttpOnlyCookies(true)
                .build();

        assertEquals(15, config.maxCookieCount());
        assertEquals(64, config.maxCookieNameLength());
        assertEquals(1024, config.maxCookieValueLength());
        assertTrue(config.requireSecureCookies());
        assertTrue(config.requireHttpOnlyCookies());
    }

    @Test
    void shouldSetCookieSecurityInOneCall() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .cookieSecurity(true, true, 10, 32, 512)
                .build();

        assertTrue(config.requireSecureCookies());
        assertTrue(config.requireHttpOnlyCookies());
        assertEquals(10, config.maxCookieCount());
        assertEquals(32, config.maxCookieNameLength());
        assertEquals(512, config.maxCookieValueLength());
    }

    @Test
    void shouldValidateCookieConstraints() {
        // Cookie count can be 0
        SecurityConfiguration.builder().maxCookieCount(0);

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxCookieCount(-1));
        assertTrue(thrown.getMessage().contains("maxCookieCount must be non-negative"));

        IllegalArgumentException thrown2 = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxCookieNameLength(0));
        assertTrue(thrown2.getMessage().contains("maxCookieNameLength must be positive"));

        IllegalArgumentException thrown3 = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxCookieValueLength(0));
        assertTrue(thrown3.getMessage().contains("maxCookieValueLength must be positive"));
    }

    @Test
    void shouldSetBodySecuritySettings() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxBodySize(2 * 1024 * 1024)
                .build();

        assertEquals(2 * 1024 * 1024, config.maxBodySize());
    }

    @Test
    void shouldManageAllowedContentTypes() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .addAllowedContentType("application/json")
                .addAllowedContentType("text/plain")
                .build();

        assertNotNull(config.allowedContentTypes());
        assertEquals(2, config.allowedContentTypes().size());
        assertTrue(config.allowedContentTypes().contains("application/json"));
        assertTrue(config.allowedContentTypes().contains("text/plain"));
    }

    @Test
    void shouldSetAllowedContentTypesAsSet() {
        Set<String> contentTypes = Set.of("application/xml", "text/html");
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowedContentTypes(contentTypes)
                .build();

        assertEquals(2, config.allowedContentTypes().size());
        assertTrue(config.allowedContentTypes().contains("application/xml"));
        assertTrue(config.allowedContentTypes().contains("text/html"));
    }

    @Test
    void shouldManageBlockedContentTypes() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .addBlockedContentType("application/x-executable")
                .addBlockedContentType("text/x-script")
                .build();

        assertEquals(2, config.blockedContentTypes().size());
        assertTrue(config.blockedContentTypes().contains("application/x-executable"));
        assertTrue(config.blockedContentTypes().contains("text/x-script"));
    }

    @Test
    void shouldSetBlockedContentTypesAsSet() {
        Set<String> contentTypes = Set.of("application/octet-stream", "text/x-shellscript");
        SecurityConfiguration config = SecurityConfiguration.builder()
                .blockedContentTypes(contentTypes)
                .build();

        assertEquals(2, config.blockedContentTypes().size());
        assertTrue(config.blockedContentTypes().contains("application/octet-stream"));
        assertTrue(config.blockedContentTypes().contains("text/x-shellscript"));
    }

    @Test
    void shouldSetBodySecurityInOneCall() {
        Set<String> allowedTypes = Set.of("application/json", "text/plain");
        SecurityConfiguration config = SecurityConfiguration.builder()
                .bodySecurity(1024 * 1024, allowedTypes)
                .build();

        assertEquals(1024 * 1024, config.maxBodySize());
        assertEquals(2, config.allowedContentTypes().size());
        assertTrue(config.allowedContentTypes().contains("application/json"));
    }

    @Test
    void shouldValidateBodySizeNonNegative() {
        // Body size can be 0
        SecurityConfiguration.builder().maxBodySize(0);

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxBodySize(-1));
        assertTrue(thrown.getMessage().contains("maxBodySize must be non-negative"));
    }

    @Test
    void shouldRejectNullContentTypes() {
        assertThrows(NullPointerException.class, () ->
                SecurityConfiguration.builder().addAllowedContentType(null));

        assertThrows(NullPointerException.class, () ->
                SecurityConfiguration.builder().addBlockedContentType(null));

        assertThrows(NullPointerException.class, () ->
                SecurityConfiguration.builder().blockedContentTypes(null));
    }

    @Test
    void shouldSetEncodingSecuritySettings() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowNullBytes(true)
                .allowControlCharacters(true)
                .allowHighBitCharacters(false)
                .normalizeUnicode(true)
                .build();

        assertTrue(config.allowNullBytes());
        assertTrue(config.allowControlCharacters());
        assertFalse(config.allowHighBitCharacters());
        assertTrue(config.normalizeUnicode());
    }

    @Test
    void shouldSetEncodingSecurityInOneCall() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .encoding(true, false, true, false)
                .build();

        assertTrue(config.allowNullBytes());
        assertFalse(config.allowControlCharacters());
        assertTrue(config.allowHighBitCharacters());
        assertFalse(config.normalizeUnicode());
    }

    @Test
    void shouldSetGeneralPolicySettings() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .caseSensitiveComparison(true)
                .failOnSuspiciousPatterns(true)
                .logSecurityViolations(false)
                .build();

        assertTrue(config.caseSensitiveComparison());
        assertTrue(config.failOnSuspiciousPatterns());
        assertFalse(config.logSecurityViolations());
    }

    @Test
    void shouldSetPoliciesInOneCall() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .policies(true, false, true)
                .build();

        assertTrue(config.caseSensitiveComparison());
        assertFalse(config.failOnSuspiciousPatterns());
        assertTrue(config.logSecurityViolations());
    }

    @Test
    void shouldSupportMethodChaining() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxPathLength(1024)
                .allowPathTraversal(false)
                .maxParameterCount(50)
                .requireSecureCookies(true)
                .allowNullBytes(false)
                .caseSensitiveComparison(true)
                .build();

        assertEquals(1024, config.maxPathLength());
        assertFalse(config.allowPathTraversal());
        assertEquals(50, config.maxParameterCount());
        assertTrue(config.requireSecureCookies());
        assertFalse(config.allowNullBytes());
        assertTrue(config.caseSensitiveComparison());
    }

    @Test
    void shouldCreateComplexConfiguration() {
        Set<String> allowedHeaders = Set.of("Authorization", "Content-Type", "X-Custom");
        Set<String> blockedHeaders = Set.of("X-Debug", "X-Internal", "X-Admin");
        Set<String> allowedContentTypes = Set.of("application/json", "text/plain", "text/html");
        Set<String> blockedContentTypes = Set.of("application/x-executable", "text/x-script");

        SecurityConfiguration config = SecurityConfiguration.builder()
                .pathSecurity(2048, false)
                .parameterSecurity(75, 100, 1500)
                .headerSecurity(40, 100, 1500)
                .allowedHeaderNames(allowedHeaders)
                .blockedHeaderNames(blockedHeaders)
                .cookieSecurity(true, true, 15, 100, 1500)
                .bodySecurity(3 * 1024 * 1024, allowedContentTypes)
                .blockedContentTypes(blockedContentTypes)
                .encoding(false, false, true, true)
                .policies(false, true, true)
                .build();

        // Verify all settings
        assertEquals(2048, config.maxPathLength());
        assertFalse(config.allowPathTraversal());
        assertEquals(75, config.maxParameterCount());
        assertEquals(100, config.maxParameterNameLength());
        assertEquals(1500, config.maxParameterValueLength());
        assertEquals(40, config.maxHeaderCount());
        assertEquals(3, config.allowedHeaderNames().size());
        assertEquals(3, config.blockedHeaderNames().size());
        assertTrue(config.requireSecureCookies());
        assertTrue(config.requireHttpOnlyCookies());
        assertEquals(3 * 1024 * 1024, config.maxBodySize());
        assertEquals(3, config.allowedContentTypes().size());
        assertEquals(2, config.blockedContentTypes().size());
        assertFalse(config.allowNullBytes());
        assertTrue(config.allowHighBitCharacters());
        assertTrue(config.normalizeUnicode());
        assertFalse(config.caseSensitiveComparison());
        assertTrue(config.failOnSuspiciousPatterns());
        assertTrue(config.logSecurityViolations());
    }

    @Test
    void shouldHandleNullAllowedSets() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowedHeaderNames(null)
                .allowedContentTypes(null)
                .build();

        assertNull(config.allowedHeaderNames());
        assertNull(config.allowedContentTypes());
    }

    @Test
    void shouldPreventModificationOfBuilderSetsAfterBuilding() {
        SecurityConfigurationBuilder builder = SecurityConfiguration.builder();
        builder.addBlockedHeaderName("X-Test");

        SecurityConfiguration config = builder.build();

        // Adding more items to builder shouldn't affect already built configuration
        builder.addBlockedHeaderName("X-Modified");

        assertEquals(1, config.blockedHeaderNames().size());
        assertTrue(config.blockedHeaderNames().contains("X-Test"));
        assertFalse(config.blockedHeaderNames().contains("X-Modified"));
    }
}