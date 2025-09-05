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
package de.cuioss.tools.security.http;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link Cookie}
 */
class CookieTest {

    private static final String COOKIE_NAME = "JSESSIONID";
    private static final String COOKIE_VALUE = "ABC123XYZ";
    private static final String COOKIE_ATTRIBUTES = "Domain=example.com; Path=/; Secure; HttpOnly";

    @Test
    void shouldCreateCookieWithNameValueAndAttributes() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        
        assertEquals(COOKIE_NAME, cookie.name());
        assertEquals(COOKIE_VALUE, cookie.value());
        assertEquals(COOKIE_ATTRIBUTES, cookie.attributes());
    }

    @Test
    void shouldCreateCookieWithNullValues() {
        Cookie cookie1 = new Cookie(null, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie cookie2 = new Cookie(COOKIE_NAME, null, COOKIE_ATTRIBUTES);
        Cookie cookie3 = new Cookie(COOKIE_NAME, COOKIE_VALUE, null);
        Cookie cookie4 = new Cookie(null, null, null);
        
        assertNull(cookie1.name());
        assertEquals(COOKIE_VALUE, cookie1.value());
        assertEquals(COOKIE_ATTRIBUTES, cookie1.attributes());
        
        assertEquals(COOKIE_NAME, cookie2.name());
        assertNull(cookie2.value());
        assertEquals(COOKIE_ATTRIBUTES, cookie2.attributes());
        
        assertEquals(COOKIE_NAME, cookie3.name());
        assertEquals(COOKIE_VALUE, cookie3.value());
        assertNull(cookie3.attributes());
        
        assertNull(cookie4.name());
        assertNull(cookie4.value());
        assertNull(cookie4.attributes());
    }

    @Test
    void shouldCreateSimpleCookie() {
        Cookie cookie = Cookie.simple("session", "token123");
        
        assertEquals("session", cookie.name());
        assertEquals("token123", cookie.value());
        assertEquals("", cookie.attributes());
    }

    @Test
    void shouldDetectCookieWithName() {
        Cookie withName = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        Cookie withoutName = new Cookie(null, COOKIE_VALUE, "");
        Cookie withEmptyName = new Cookie("", COOKIE_VALUE, "");
        
        assertTrue(withName.hasName());
        assertFalse(withoutName.hasName());
        assertFalse(withEmptyName.hasName());
    }

    @Test
    void shouldDetectCookieWithValue() {
        Cookie withValue = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        Cookie withoutValue = new Cookie(COOKIE_NAME, null, "");
        Cookie withEmptyValue = new Cookie(COOKIE_NAME, "", "");
        
        assertTrue(withValue.hasValue());
        assertFalse(withoutValue.hasValue());
        assertFalse(withEmptyValue.hasValue());
    }

    @Test
    void shouldDetectCookieWithAttributes() {
        Cookie withAttributes = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie withoutAttributes = new Cookie(COOKIE_NAME, COOKIE_VALUE, null);
        Cookie withEmptyAttributes = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        
        assertTrue(withAttributes.hasAttributes());
        assertFalse(withoutAttributes.hasAttributes());
        assertFalse(withEmptyAttributes.hasAttributes());
    }

    @Test
    void shouldDetectSecureCookie() {
        Cookie secureCookie1 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure");
        Cookie secureCookie2 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Domain=test.com; Secure; HttpOnly");
        Cookie secureCookie3 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "secure"); // Case insensitive
        Cookie nonSecureCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "HttpOnly");
        
        assertTrue(secureCookie1.isSecure());
        assertTrue(secureCookie2.isSecure());
        assertTrue(secureCookie3.isSecure());
        assertFalse(nonSecureCookie.isSecure());
    }

    @Test
    void shouldDetectHttpOnlyCookie() {
        Cookie httpOnlyCookie1 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "HttpOnly");
        Cookie httpOnlyCookie2 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Domain=test.com; Secure; HttpOnly");
        Cookie httpOnlyCookie3 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "httponly"); // Case insensitive
        Cookie nonHttpOnlyCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure");
        
        assertTrue(httpOnlyCookie1.isHttpOnly());
        assertTrue(httpOnlyCookie2.isHttpOnly());
        assertTrue(httpOnlyCookie3.isHttpOnly());
        assertFalse(nonHttpOnlyCookie.isHttpOnly());
    }

    @Test
    void shouldExtractDomain() {
        Cookie cookieWithDomain = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Domain=example.com; Secure");
        Cookie cookieWithoutDomain = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly");
        
        assertEquals("example.com", cookieWithDomain.getDomain());
        assertNull(cookieWithoutDomain.getDomain());
    }

    @Test
    void shouldExtractPath() {
        Cookie cookieWithPath = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Path=/admin; Secure");
        Cookie cookieWithoutPath = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly");
        
        assertEquals("/admin", cookieWithPath.getPath());
        assertNull(cookieWithoutPath.getPath());
    }

    @Test
    void shouldExtractSameSite() {
        Cookie strictCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "SameSite=Strict");
        Cookie laxCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "SameSite=Lax; Secure");
        Cookie noneCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "SameSite=None");
        Cookie cookieWithoutSameSite = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure");
        
        assertEquals("Strict", strictCookie.getSameSite());
        assertEquals("Lax", laxCookie.getSameSite());
        assertEquals("None", noneCookie.getSameSite());
        assertNull(cookieWithoutSameSite.getSameSite());
    }

    @Test
    void shouldExtractMaxAge() {
        Cookie cookieWithMaxAge = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Max-Age=3600; Secure");
        Cookie cookieWithoutMaxAge = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly");
        
        assertEquals("3600", cookieWithMaxAge.getMaxAge());
        assertNull(cookieWithoutMaxAge.getMaxAge());
    }

    @Test
    void shouldExtractAttributeNames() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, 
            "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict");
        Cookie simpleCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        
        List<String> attributeNames = cookie.getAttributeNames();
        assertEquals(5, attributeNames.size());
        assertTrue(attributeNames.contains("Domain"));
        assertTrue(attributeNames.contains("Path"));
        assertTrue(attributeNames.contains("Secure"));
        assertTrue(attributeNames.contains("HttpOnly"));
        assertTrue(attributeNames.contains("SameSite"));
        
        assertTrue(simpleCookie.getAttributeNames().isEmpty());
    }

    @Test
    void shouldReturnNameOrDefault() {
        Cookie withName = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        Cookie withoutName = new Cookie(null, COOKIE_VALUE, "");
        
        assertEquals(COOKIE_NAME, withName.nameOrDefault("default"));
        assertEquals("default", withoutName.nameOrDefault("default"));
    }

    @Test
    void shouldReturnValueOrDefault() {
        Cookie withValue = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        Cookie withoutValue = new Cookie(COOKIE_NAME, null, "");
        
        assertEquals(COOKIE_VALUE, withValue.valueOrDefault("default"));
        assertEquals("default", withoutValue.valueOrDefault("default"));
    }

    @Test
    void shouldGenerateCookieString() {
        Cookie simpleCookie = new Cookie("name", "value", "");
        Cookie cookieWithAttributes = new Cookie("auth", "token123", "Secure; HttpOnly");
        Cookie cookieWithNullName = new Cookie(null, "value", "");
        Cookie cookieWithNullValue = new Cookie("name", null, "");
        
        assertEquals("name=value", simpleCookie.toCookieString());
        assertEquals("auth=token123; Secure; HttpOnly", cookieWithAttributes.toCookieString());
        assertEquals("=value", cookieWithNullName.toCookieString());
        assertEquals("name=", cookieWithNullValue.toCookieString());
    }

    @Test
    void shouldCreateCookieWithNewName() {
        Cookie original = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie renamed = original.withName("newName");
        
        assertEquals("newName", renamed.name());
        assertEquals(COOKIE_VALUE, renamed.value());
        assertEquals(COOKIE_ATTRIBUTES, renamed.attributes());
        assertEquals(COOKIE_NAME, original.name()); // Original unchanged
    }

    @Test
    void shouldCreateCookieWithNewValue() {
        Cookie original = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie newValue = original.withValue("newValue");
        
        assertEquals(COOKIE_NAME, newValue.name());
        assertEquals("newValue", newValue.value());
        assertEquals(COOKIE_ATTRIBUTES, newValue.attributes());
        assertEquals(COOKIE_VALUE, original.value()); // Original unchanged
    }

    @Test
    void shouldCreateCookieWithNewAttributes() {
        Cookie original = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie newAttributes = original.withAttributes("Secure");
        
        assertEquals(COOKIE_NAME, newAttributes.name());
        assertEquals(COOKIE_VALUE, newAttributes.value());
        assertEquals("Secure", newAttributes.attributes());
        assertEquals(COOKIE_ATTRIBUTES, original.attributes()); // Original unchanged
    }

    @Test
    void shouldSupportEquality() {
        Cookie cookie1 = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie cookie2 = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie cookie3 = new Cookie("other", COOKIE_VALUE, COOKIE_ATTRIBUTES);
        
        assertEquals(cookie1, cookie2);
        assertNotEquals(cookie1, cookie3);
        assertEquals(cookie1.hashCode(), cookie2.hashCode());
    }

    @Test
    void shouldSupportToString() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        String string = cookie.toString();
        
        assertTrue(string.contains(COOKIE_NAME));
        assertTrue(string.contains(COOKIE_VALUE));
        assertTrue(string.contains(COOKIE_ATTRIBUTES));
    }

    @Test
    void shouldHandleAttributesWithSpaces() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Domain = example.com ; Path = / ");
        
        // The current implementation requires exact "attribute=" pattern without spaces around =
        // This is actually correct per RFC 6265, where spaces around = are not standard
        assertNull(cookie.getDomain()); // "Domain = " is not the same as "Domain="
        assertNull(cookie.getPath()); // "Path = " is not the same as "Path="
    }

    @Test
    void shouldHandleComplexAttributeValues() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, 
            "Domain=sub.example.com; Path=/admin/dashboard; Max-Age=86400");
        
        assertEquals("sub.example.com", cookie.getDomain());
        assertEquals("/admin/dashboard", cookie.getPath());
        assertEquals("86400", cookie.getMaxAge());
    }

    @Test
    void shouldHandleCaseInsensitiveAttributeExtraction() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, 
            "domain=example.com; PATH=/test; max-age=3600");
        
        assertEquals("example.com", cookie.getDomain());
        assertEquals("/test", cookie.getPath());
        assertEquals("3600", cookie.getMaxAge());
    }

    @Test
    void shouldHandleAttributesWithoutValues() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly; SameSite");
        
        List<String> attributeNames = cookie.getAttributeNames();
        assertEquals(3, attributeNames.size());
        assertTrue(attributeNames.contains("Secure"));
        assertTrue(attributeNames.contains("HttpOnly"));
        assertTrue(attributeNames.contains("SameSite"));
        
        assertTrue(cookie.isSecure());
        assertTrue(cookie.isHttpOnly());
        assertNull(cookie.getSameSite()); // No value provided for SameSite
    }

    @Test
    void shouldHandleEmptyAttributeSegments() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, ";;Secure;;HttpOnly;;");
        
        assertTrue(cookie.isSecure());
        assertTrue(cookie.isHttpOnly());
    }

    @Test
    void shouldBeImmutable() {
        Cookie original = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        
        Cookie withNewName = original.withName("new");
        Cookie withNewValue = original.withValue("new");
        Cookie withNewAttributes = original.withAttributes("new");
        
        // Original should be unchanged
        assertEquals(COOKIE_NAME, original.name());
        assertEquals(COOKIE_VALUE, original.value());
        assertEquals(COOKIE_ATTRIBUTES, original.attributes());
        
        // New instances should have changes
        assertEquals("new", withNewName.name());
        assertEquals("new", withNewValue.value());
        assertEquals("new", withNewAttributes.attributes());
    }

    @Test
    void shouldHandleSpecialCharactersInValues() {
        Cookie cookie = new Cookie("special&name", "value with spaces", 
            "Domain=exam-ple.com; Path=/path with spaces");
        
        assertEquals("special&name", cookie.name());
        assertEquals("value with spaces", cookie.value());
        assertEquals("exam-ple.com", cookie.getDomain());
        assertEquals("/path with spaces", cookie.getPath());
    }
}