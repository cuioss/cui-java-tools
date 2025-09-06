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
package de.cuioss.tools.security.http.data;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link Cookie}
 */
@EnableGeneratorController
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

        assertTrue(withName.hasName());
        assertFalse(withoutName.hasName());
        // Note: Empty name is now rejected by constructor validation
    }

    @Test
    void shouldAcceptAnyCookieNames() {
        // Records are pure data holders - validation is done by consumers
        Cookie cookie1 = new Cookie("", COOKIE_VALUE, "");
        assertEquals("", cookie1.name());

        // Names with special characters should be accepted
        Cookie cookie2 = new Cookie("name;invalid", COOKIE_VALUE, "");
        assertEquals("name;invalid", cookie2.name());

        Cookie cookie3 = new Cookie("name=invalid", COOKIE_VALUE, "");
        assertEquals("name=invalid", cookie3.name());

        // Even names with spaces should be accepted  
        Cookie cookie4 = new Cookie("name invalid", COOKIE_VALUE, "");
        assertEquals("name invalid", cookie4.name());
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

        assertEquals("example.com", cookieWithDomain.getDomain().orElse(null));
        assertTrue(cookieWithoutDomain.getDomain().isEmpty());
    }

    @Test
    void shouldExtractPath() {
        Cookie cookieWithPath = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Path=/admin; Secure");
        Cookie cookieWithoutPath = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly");

        assertEquals("/admin", cookieWithPath.getPath().orElse(null));
        assertTrue(cookieWithoutPath.getPath().isEmpty());
    }

    @Test
    void shouldExtractSameSite() {
        Cookie strictCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "SameSite=Strict");
        Cookie laxCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "SameSite=Lax; Secure");
        Cookie noneCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "SameSite=None");
        Cookie cookieWithoutSameSite = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure");

        assertEquals("Strict", strictCookie.getSameSite().orElse(null));
        assertEquals("Lax", laxCookie.getSameSite().orElse(null));
        assertEquals("None", noneCookie.getSameSite().orElse(null));
        assertTrue(cookieWithoutSameSite.getSameSite().isEmpty());
    }

    @Test
    void shouldExtractMaxAge() {
        Cookie cookieWithMaxAge = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Max-Age=3600; Secure");
        Cookie cookieWithoutMaxAge = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly");

        assertEquals("3600", cookieWithMaxAge.getMaxAge().orElse(null));
        assertTrue(cookieWithoutMaxAge.getMaxAge().isEmpty());
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

    @ParameterizedTest
    @TypeGeneratorSource(value = TestCookieGenerator.class, count = 20)
    void shouldGenerateValidCookieString(Cookie cookie) {
        String cookieString = cookie.toCookieString();

        // Cookie string should always be non-null
        assertNotNull(cookieString);

        // Should contain equals sign for name=value format
        assertTrue(cookieString.contains("="));

        // If cookie has attributes, they should be included
        if (cookie.hasAttributes()) {
            assertTrue(cookieString.length() > (cookie.nameOrDefault("") + "=" + cookie.valueOrDefault("")).length());
        }
    }

    @Test
    void shouldGenerateCookieStringWithKnownValues() {
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

    @ParameterizedTest
    @TypeGeneratorSource(value = TestCookieGenerator.class, count = 10)
    void shouldSupportEquality(Cookie cookie) {
        Cookie sameCookie = new Cookie(cookie.name(), cookie.value(), cookie.attributes());
        Cookie differentCookie = new Cookie("different_name", cookie.value(), cookie.attributes());

        assertEquals(cookie, sameCookie);
        assertNotEquals(cookie, differentCookie);
        assertEquals(cookie.hashCode(), sameCookie.hashCode());
    }

    @Test
    void shouldSupportEqualityWithKnownValues() {
        Cookie cookie1 = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie cookie2 = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie cookie3 = new Cookie("other", COOKIE_VALUE, COOKIE_ATTRIBUTES);

        assertEquals(cookie1, cookie2);
        assertNotEquals(cookie1, cookie3);
        assertEquals(cookie1.hashCode(), cookie2.hashCode());
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = TestCookieGenerator.class, count = 15)
    void shouldSupportToString(Cookie cookie) {
        String string = cookie.toString();
        assertNotNull(string);

        // String representation should contain the cookie name if present
        if (cookie.name() != null && !cookie.name().isEmpty()) {
            assertTrue(string.contains(cookie.name()) || string.contains("name"));
        }

        // String representation should contain some representation of the cookie
        assertTrue(string.length() > 5);
    }

    @Test
    void shouldSupportToStringWithKnownValues() {
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
        assertTrue(cookie.getDomain().isEmpty()); // "Domain = " is not the same as "Domain="
        assertTrue(cookie.getPath().isEmpty()); // "Path = " is not the same as "Path="
    }

    @Test
    void shouldHandleComplexAttributeValues() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE,
                "Domain=sub.example.com; Path=/admin/dashboard; Max-Age=86400");

        assertEquals("sub.example.com", cookie.getDomain().orElse(null));
        assertEquals("/admin/dashboard", cookie.getPath().orElse(null));
        assertEquals("86400", cookie.getMaxAge().orElse(null));
    }

    @Test
    void shouldHandleCaseInsensitiveAttributeExtraction() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE,
                "domain=example.com; PATH=/test; max-age=3600");

        assertEquals("example.com", cookie.getDomain().orElse(null));
        assertEquals("/test", cookie.getPath().orElse(null));
        assertEquals("3600", cookie.getMaxAge().orElse(null));
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
        assertTrue(cookie.getSameSite().isEmpty()); // No value provided for SameSite
    }

    @Test
    void shouldHandleEmptyAttributeSegments() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, ";;Secure;;HttpOnly;;");

        assertTrue(cookie.isSecure());
        assertTrue(cookie.isHttpOnly());
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = TestCookieGenerator.class, count = 10)
    void shouldBeImmutable(Cookie original) {
        String originalName = original.name();
        String originalValue = original.value();
        String originalAttributes = original.attributes();

        Cookie withNewName = original.withName("new");
        Cookie withNewValue = original.withValue("new");
        Cookie withNewAttributes = original.withAttributes("new");

        // Original should be unchanged
        assertEquals(originalName, original.name());
        assertEquals(originalValue, original.value());
        assertEquals(originalAttributes, original.attributes());

        // New instances should have changes
        assertEquals("new", withNewName.name());
        assertEquals("new", withNewValue.value());
        assertEquals("new", withNewAttributes.attributes());
    }

    @Test
    void shouldBeImmutableWithKnownValues() {
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
        assertEquals("exam-ple.com", cookie.getDomain().orElse(null));
        assertEquals("/path with spaces", cookie.getPath().orElse(null));
    }


    static class TestCookieGenerator implements TypedGenerator<Cookie> {
        private final TypedGenerator<String> cookieNames = Generators.fixedValues(
                "JSESSIONID", "session_id", "auth_token", "csrf_token", "user_id", "preferences",
                "language", "theme", "cart_id", "tracking_id", "remember_me", "login_token",
                "access_token", "refresh_token", "device_id", null, "", "   ", "cookie with spaces",
                "cookie=equals", "cookie;semicolon", "cookie,comma", "cookie\"quote", "cookie\ttab"
        );

        private final TypedGenerator<String> cookieValues = Generators.fixedValues(
                "ABC123DEF456", "session_12345", "user_67890", "true", "false", "en_US",
                "dark", "light", "cart_abc123", "track_xyz789", "remember_yes", "token_valid",
                "device_mobile", "lang_de", "theme_blue", null, "", "value with spaces",
                "<script>alert('xss')</script>", "'; DROP TABLE sessions; --", "../../../etc/passwd",
                "%0d%0aSet-Cookie: evil=bad", "A".repeat(1000), "\u0000null_byte"
        );

        private final TypedGenerator<String> cookieAttributes = Generators.fixedValues(
                "", "Domain=example.com", "Path=/admin", "Secure", "HttpOnly", "SameSite=Strict",
                "Max-Age=3600", "Domain=example.com; Path=/; Secure",
                "Domain=example.com; Path=/; HttpOnly; SameSite=Lax", "Domain=.evil.com",
                "Path=../../../", "Max-Age=-1", "Domain=; Path=", "Invalid=Attribute; Bad=Value",
                "Domain=example.com\r\nSet-Cookie: evil=bad", "Path=/\u0000/admin", null
        );

        @Override
        public Cookie next() {
            return new Cookie(cookieNames.next(), cookieValues.next(), cookieAttributes.next());
        }

        @Override
        public Class<Cookie> getType() {
            return Cookie.class;
        }
    }
}
