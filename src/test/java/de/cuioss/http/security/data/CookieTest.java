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

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.http.security.generators.cookie.ValidCookieGenerator;
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

        assertEquals(COOKIE_NAME, cookie.name(), "Cookie should preserve the provided name");
        assertEquals(COOKIE_VALUE, cookie.value(), "Cookie should preserve the provided value");
        assertEquals(COOKIE_ATTRIBUTES, cookie.attributes(), "Cookie should preserve the provided attributes");
    }

    @Test
    void shouldCreateCookieWithNullValues() {
        Cookie cookie1 = new Cookie(null, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie cookie2 = new Cookie(COOKIE_NAME, null, COOKIE_ATTRIBUTES);
        Cookie cookie3 = new Cookie(COOKIE_NAME, COOKIE_VALUE, null);
        Cookie cookie4 = new Cookie(null, null, null);

        assertNull(cookie1.name(), "Cookie should accept null name");
        assertEquals(COOKIE_VALUE, cookie1.value(), "Cookie with null name should preserve value");
        assertEquals(COOKIE_ATTRIBUTES, cookie1.attributes(), "Cookie with null name should preserve attributes");

        assertEquals(COOKIE_NAME, cookie2.name(), "Cookie with null value should preserve name");
        assertNull(cookie2.value(), "Cookie should accept null value");
        assertEquals(COOKIE_ATTRIBUTES, cookie2.attributes(), "Cookie with null value should preserve attributes");

        assertEquals(COOKIE_NAME, cookie3.name(), "Cookie with null attributes should preserve name");
        assertEquals(COOKIE_VALUE, cookie3.value(), "Cookie with null attributes should preserve value");
        assertNull(cookie3.attributes(), "Cookie should accept null attributes");

        assertNull(cookie4.name(), "Cookie should accept all null values for name");
        assertNull(cookie4.value(), "Cookie should accept all null values for value");
        assertNull(cookie4.attributes(), "Cookie should accept all null values for attributes");
    }

    @Test
    void shouldCreateSimpleCookie() {
        Cookie cookie = Cookie.simple("session", "token123");

        assertEquals("session", cookie.name(), "Simple cookie should use provided name");
        assertEquals("token123", cookie.value(), "Simple cookie should use provided value");
        assertEquals("", cookie.attributes(), "Simple cookie should have empty attributes");
    }

    @Test
    void shouldDetectCookieWithName() {
        Cookie withName = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        Cookie withoutName = new Cookie(null, COOKIE_VALUE, "");

        assertTrue(withName.hasName(), "Cookie with non-null name should return true for hasName()");
        assertFalse(withoutName.hasName(), "Cookie with null name should return false for hasName()");
        // Note: Empty name is now rejected by constructor validation
    }

    @Test
    void shouldAcceptAnyCookieNames() {
        // Records are pure data holders - validation is done by consumers
        Cookie cookie1 = new Cookie("", COOKIE_VALUE, "");
        assertEquals("", cookie1.name(), "Cookie should accept empty string as name");

        // Names with special characters should be accepted
        Cookie cookie2 = new Cookie("name;invalid", COOKIE_VALUE, "");
        assertEquals("name;invalid", cookie2.name(), "Cookie should accept names with semicolons");

        Cookie cookie3 = new Cookie("name=invalid", COOKIE_VALUE, "");
        assertEquals("name=invalid", cookie3.name(), "Cookie should accept names with equals signs");

        // Even names with spaces should be accepted
        Cookie cookie4 = new Cookie("name invalid", COOKIE_VALUE, "");
        assertEquals("name invalid", cookie4.name(), "Cookie should accept names with spaces");
    }

    @Test
    void shouldDetectCookieWithValue() {
        Cookie withValue = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        Cookie withoutValue = new Cookie(COOKIE_NAME, null, "");
        Cookie withEmptyValue = new Cookie(COOKIE_NAME, "", "");

        assertTrue(withValue.hasValue(), "Cookie with non-null, non-empty value should return true for hasValue()");
        assertFalse(withoutValue.hasValue(), "Cookie with null value should return false for hasValue()");
        assertFalse(withEmptyValue.hasValue(), "Cookie with empty value should return false for hasValue()");
    }

    @Test
    void shouldDetectCookieWithAttributes() {
        Cookie withAttributes = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie withoutAttributes = new Cookie(COOKIE_NAME, COOKIE_VALUE, null);
        Cookie withEmptyAttributes = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");

        assertTrue(withAttributes.hasAttributes(), "Cookie with non-null, non-empty attributes should return true for hasAttributes()");
        assertFalse(withoutAttributes.hasAttributes(), "Cookie with null attributes should return false for hasAttributes()");
        assertFalse(withEmptyAttributes.hasAttributes(), "Cookie with empty attributes should return false for hasAttributes()");
    }

    @Test
    void shouldDetectSecureCookie() {
        Cookie secureCookie1 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure");
        Cookie secureCookie2 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Domain=test.com; Secure; HttpOnly");
        Cookie secureCookie3 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "secure"); // Case insensitive
        Cookie nonSecureCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "HttpOnly");

        assertTrue(secureCookie1.isSecure(), "Cookie with 'Secure' attribute should return true for isSecure()");
        assertTrue(secureCookie2.isSecure(), "Cookie with 'Secure' among other attributes should return true for isSecure()");
        assertTrue(secureCookie3.isSecure(), "Cookie with case-insensitive 'secure' should return true for isSecure()");
        assertFalse(nonSecureCookie.isSecure(), "Cookie without 'Secure' attribute should return false for isSecure()");
    }

    @Test
    void shouldDetectHttpOnlyCookie() {
        Cookie httpOnlyCookie1 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "HttpOnly");
        Cookie httpOnlyCookie2 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Domain=test.com; Secure; HttpOnly");
        Cookie httpOnlyCookie3 = new Cookie(COOKIE_NAME, COOKIE_VALUE, "httponly"); // Case insensitive
        Cookie nonHttpOnlyCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure");

        assertTrue(httpOnlyCookie1.isHttpOnly(), "Cookie with 'HttpOnly' attribute should return true for isHttpOnly()");
        assertTrue(httpOnlyCookie2.isHttpOnly(), "Cookie with 'HttpOnly' among other attributes should return true for isHttpOnly()");
        assertTrue(httpOnlyCookie3.isHttpOnly(), "Cookie with case-insensitive 'httponly' should return true for isHttpOnly()");
        assertFalse(nonHttpOnlyCookie.isHttpOnly(), "Cookie without 'HttpOnly' attribute should return false for isHttpOnly()");
    }

    @Test
    void shouldExtractDomain() {
        Cookie cookieWithDomain = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Domain=example.com; Secure");
        Cookie cookieWithoutDomain = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly");

        assertEquals("example.com", cookieWithDomain.getDomain().orElse(null), "Cookie should extract Domain attribute value correctly");
        assertTrue(cookieWithoutDomain.getDomain().isEmpty(), "Cookie without Domain attribute should return empty Optional");
    }

    @Test
    void shouldExtractPath() {
        Cookie cookieWithPath = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Path=/admin; Secure");
        Cookie cookieWithoutPath = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly");

        assertEquals("/admin", cookieWithPath.getPath().orElse(null), "Cookie should extract Path attribute value correctly");
        assertTrue(cookieWithoutPath.getPath().isEmpty(), "Cookie without Path attribute should return empty Optional");
    }

    @Test
    void shouldExtractSameSite() {
        Cookie strictCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "SameSite=Strict");
        Cookie laxCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "SameSite=Lax; Secure");
        Cookie noneCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "SameSite=None");
        Cookie cookieWithoutSameSite = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure");

        assertEquals("Strict", strictCookie.getSameSite().orElse(null), "Cookie should extract SameSite=Strict value correctly");
        assertEquals("Lax", laxCookie.getSameSite().orElse(null), "Cookie should extract SameSite=Lax value correctly");
        assertEquals("None", noneCookie.getSameSite().orElse(null), "Cookie should extract SameSite=None value correctly");
        assertTrue(cookieWithoutSameSite.getSameSite().isEmpty(), "Cookie without SameSite attribute should return empty Optional");
    }

    @Test
    void shouldExtractMaxAge() {
        Cookie cookieWithMaxAge = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Max-Age=3600; Secure");
        Cookie cookieWithoutMaxAge = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly");

        assertEquals("3600", cookieWithMaxAge.getMaxAge().orElse(null), "Cookie should extract Max-Age attribute value correctly");
        assertTrue(cookieWithoutMaxAge.getMaxAge().isEmpty(), "Cookie without Max-Age attribute should return empty Optional");
    }

    @Test
    void shouldExtractAttributeNames() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE,
                "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict");
        Cookie simpleCookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");

        List<String> attributeNames = cookie.getAttributeNames();
        assertEquals(5, attributeNames.size(), "Cookie should extract all 5 attribute names correctly");
        assertTrue(attributeNames.contains("Domain"), "Extracted attribute names should include Domain");
        assertTrue(attributeNames.contains("Path"), "Extracted attribute names should include Path");
        assertTrue(attributeNames.contains("Secure"), "Extracted attribute names should include Secure");
        assertTrue(attributeNames.contains("HttpOnly"), "Extracted attribute names should include HttpOnly");
        assertTrue(attributeNames.contains("SameSite"), "Extracted attribute names should include SameSite");

        assertTrue(simpleCookie.getAttributeNames().isEmpty(), "Cookie with no attributes should return empty attribute names list");
    }

    @Test
    void shouldReturnNameOrDefault() {
        Cookie withName = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        Cookie withoutName = new Cookie(null, COOKIE_VALUE, "");

        assertEquals(COOKIE_NAME, withName.nameOrDefault("default"), "nameOrDefault should return actual name when name is not null");
        assertEquals("default", withoutName.nameOrDefault("default"), "nameOrDefault should return default value when name is null");
    }

    @Test
    void shouldReturnValueOrDefault() {
        Cookie withValue = new Cookie(COOKIE_NAME, COOKIE_VALUE, "");
        Cookie withoutValue = new Cookie(COOKIE_NAME, null, "");

        assertEquals(COOKIE_VALUE, withValue.valueOrDefault("default"), "valueOrDefault should return actual value when value is not null");
        assertEquals("default", withoutValue.valueOrDefault("default"), "valueOrDefault should return default value when value is null");
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = ValidCookieGenerator.class, count = 20)
    void shouldGenerateValidCookieString(Cookie cookie) {
        String cookieString = cookie.toCookieString();

        // Cookie string should always be non-null
        assertNotNull(cookieString, "Generated cookie string should never be null");

        // Should contain equals sign for name=value format
        assertTrue(cookieString.contains("="), "Cookie string should contain equals sign for name=value format");

        // If cookie has attributes, they should be included
        if (cookie.hasAttributes()) {
            assertTrue(cookieString.length() > (cookie.nameOrDefault("") + "=" + cookie.valueOrDefault("")).length(), "Cookie string with attributes should be longer than just name=value");
        }
    }

    @Test
    void shouldGenerateCookieStringWithKnownValues() {
        Cookie simpleCookie = new Cookie("name", "value", "");
        Cookie cookieWithAttributes = new Cookie("auth", "token123", "Secure; HttpOnly");
        Cookie cookieWithNullName = new Cookie(null, "value", "");
        Cookie cookieWithNullValue = new Cookie("name", null, "");

        assertEquals("name=value", simpleCookie.toCookieString(), "Simple cookie should generate correct cookie string");
        assertEquals("auth=token123; Secure; HttpOnly", cookieWithAttributes.toCookieString(), "Cookie with attributes should generate correct cookie string");
        assertEquals("=value", cookieWithNullName.toCookieString(), "Cookie with null name should generate cookie string with empty name");
        assertEquals("name=", cookieWithNullValue.toCookieString(), "Cookie with null value should generate cookie string with empty value");
    }

    @Test
    void shouldCreateCookieWithNewName() {
        Cookie original = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie renamed = original.withName("newName");

        assertEquals("newName", renamed.name(), "New cookie should have the specified new name");
        assertEquals(COOKIE_VALUE, renamed.value(), "New cookie should preserve original value");
        assertEquals(COOKIE_ATTRIBUTES, renamed.attributes(), "New cookie should preserve original attributes");
        assertEquals(COOKIE_NAME, original.name(), "Original cookie should remain unchanged after withName()");
    }

    @Test
    void shouldCreateCookieWithNewValue() {
        Cookie original = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie newValue = original.withValue("newValue");

        assertEquals(COOKIE_NAME, newValue.name(), "New cookie should preserve original name");
        assertEquals("newValue", newValue.value(), "New cookie should have the specified new value");
        assertEquals(COOKIE_ATTRIBUTES, newValue.attributes(), "New cookie should preserve original attributes");
        assertEquals(COOKIE_VALUE, original.value(), "Original cookie should remain unchanged after withValue()");
    }

    @Test
    void shouldCreateCookieWithNewAttributes() {
        Cookie original = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie newAttributes = original.withAttributes("Secure");

        assertEquals(COOKIE_NAME, newAttributes.name(), "New cookie should preserve original name");
        assertEquals(COOKIE_VALUE, newAttributes.value(), "New cookie should preserve original value");
        assertEquals("Secure", newAttributes.attributes(), "New cookie should have the specified new attributes");
        assertEquals(COOKIE_ATTRIBUTES, original.attributes(), "Original cookie should remain unchanged after withAttributes()");
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = ValidCookieGenerator.class, count = 10)
    void shouldSupportEquality(Cookie cookie) {
        Cookie sameCookie = new Cookie(cookie.name(), cookie.value(), cookie.attributes());
        Cookie differentCookie = new Cookie("different_name", cookie.value(), cookie.attributes());

        assertEquals(cookie, sameCookie, "Cookies with same content should be equal");
        assertNotEquals(cookie, differentCookie, "Cookies with different content should not be equal");
        assertEquals(cookie.hashCode(), sameCookie.hashCode(), "Equal cookies should have same hash code");
    }

    @Test
    void shouldSupportEqualityWithKnownValues() {
        Cookie cookie1 = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie cookie2 = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        Cookie cookie3 = new Cookie("other", COOKIE_VALUE, COOKIE_ATTRIBUTES);

        assertEquals(cookie1, cookie2, "Cookies with identical values should be equal");
        assertNotEquals(cookie1, cookie3, "Cookies with different names should not be equal");
        assertEquals(cookie1.hashCode(), cookie2.hashCode(), "Identical cookies should have same hash code");
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = ValidCookieGenerator.class, count = 15)
    void shouldSupportToString(Cookie cookie) {
        String string = cookie.toString();
        assertNotNull(string, "Cookie toString should never return null");

        // String representation should contain the cookie name if present
        if (cookie.name() != null && !cookie.name().isEmpty()) {
            assertTrue(string.contains(cookie.name()), "toString should include the actual cookie name when present");
        }

        // String representation should contain some representation of the cookie
        assertTrue(string.length() > 5, "Cookie toString should produce meaningful string representation");
    }

    @Test
    void shouldSupportToStringWithKnownValues() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);
        String string = cookie.toString();

        assertTrue(string.contains(COOKIE_NAME), "toString should contain cookie name");
        assertTrue(string.contains(COOKIE_VALUE), "toString should contain cookie value");
        assertTrue(string.contains(COOKIE_ATTRIBUTES), "toString should contain cookie attributes");
    }

    @Test
    void shouldHandleAttributesWithSpaces() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Domain = example.com ; Path = / ");

        // The current implementation requires exact "attribute=" pattern without spaces around =
        // This is actually correct per RFC 6265, where spaces around = are not standard
        assertTrue(cookie.getDomain().isEmpty(), "Domain extraction should require exact 'Domain=' pattern without spaces");
        assertTrue(cookie.getPath().isEmpty(), "Path extraction should require exact 'Path=' pattern without spaces");
    }

    @Test
    void shouldHandleComplexAttributeValues() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE,
                "Domain=sub.example.com; Path=/admin/dashboard; Max-Age=86400");

        assertEquals("sub.example.com", cookie.getDomain().orElse(null), "Cookie should extract subdomain correctly");
        assertEquals("/admin/dashboard", cookie.getPath().orElse(null), "Cookie should extract complex path correctly");
        assertEquals("86400", cookie.getMaxAge().orElse(null), "Cookie should extract Max-Age value correctly");
    }

    @Test
    void shouldHandleCaseInsensitiveAttributeExtraction() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE,
                "domain=example.com; PATH=/test; max-age=3600");

        assertEquals("example.com", cookie.getDomain().orElse(null), "Cookie should extract domain from lowercase attribute");
        assertEquals("/test", cookie.getPath().orElse(null), "Cookie should extract path from uppercase attribute");
        assertEquals("3600", cookie.getMaxAge().orElse(null), "Cookie should extract max-age from lowercase attribute");
    }

    @Test
    void shouldHandleAttributesWithoutValues() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, "Secure; HttpOnly; SameSite");

        List<String> attributeNames = cookie.getAttributeNames();
        assertEquals(3, attributeNames.size(), "Cookie should extract 3 attribute names from boolean-style attributes");
        assertTrue(attributeNames.contains("Secure"), "Extracted attributes should include Secure");
        assertTrue(attributeNames.contains("HttpOnly"), "Extracted attributes should include HttpOnly");
        assertTrue(attributeNames.contains("SameSite"), "Extracted attributes should include SameSite");

        assertTrue(cookie.isSecure(), "Cookie with Secure attribute should return true for isSecure()");
        assertTrue(cookie.isHttpOnly(), "Cookie with HttpOnly attribute should return true for isHttpOnly()");
        assertTrue(cookie.getSameSite().isEmpty(), "SameSite without value should return empty Optional");
    }

    @Test
    void shouldHandleEmptyAttributeSegments() {
        Cookie cookie = new Cookie(COOKIE_NAME, COOKIE_VALUE, ";;Secure;;HttpOnly;;");

        assertTrue(cookie.isSecure(), "Cookie should detect Secure attribute despite empty segments");
        assertTrue(cookie.isHttpOnly(), "Cookie should detect HttpOnly attribute despite empty segments");
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = ValidCookieGenerator.class, count = 10)
    void shouldBeImmutable(Cookie original) {
        String originalName = original.name();
        String originalValue = original.value();
        String originalAttributes = original.attributes();

        Cookie withNewName = original.withName("new");
        Cookie withNewValue = original.withValue("new");
        Cookie withNewAttributes = original.withAttributes("new");

        // Original should be unchanged
        assertEquals(originalName, original.name(), "Original cookie name should remain unchanged after creating new instances");
        assertEquals(originalValue, original.value(), "Original cookie value should remain unchanged after creating new instances");
        assertEquals(originalAttributes, original.attributes(), "Original cookie attributes should remain unchanged after creating new instances");

        // New instances should have changes
        assertEquals("new", withNewName.name(), "New instance should have updated name");
        assertEquals("new", withNewValue.value(), "New instance should have updated value");
        assertEquals("new", withNewAttributes.attributes(), "New instance should have updated attributes");
    }

    @Test
    void shouldBeImmutableWithKnownValues() {
        Cookie original = new Cookie(COOKIE_NAME, COOKIE_VALUE, COOKIE_ATTRIBUTES);

        Cookie withNewName = original.withName("new");
        Cookie withNewValue = original.withValue("new");
        Cookie withNewAttributes = original.withAttributes("new");

        // Original should be unchanged
        assertEquals(COOKIE_NAME, original.name(), "Original cookie name should be preserved with known values");
        assertEquals(COOKIE_VALUE, original.value(), "Original cookie value should be preserved with known values");
        assertEquals(COOKIE_ATTRIBUTES, original.attributes(), "Original cookie attributes should be preserved with known values");

        // New instances should have changes
        assertEquals("new", withNewName.name(), "New instance should have new name with known values");
        assertEquals("new", withNewValue.value(), "New instance should have new value with known values");
        assertEquals("new", withNewAttributes.attributes(), "New instance should have new attributes with known values");
    }

    @Test
    void shouldHandleSpecialCharactersInValues() {
        Cookie cookie = new Cookie("special&name", "value with spaces",
                "Domain=exam-ple.com; Path=/path with spaces");

        assertEquals("special&name", cookie.name(), "Cookie should accept special characters in name");
        assertEquals("value with spaces", cookie.value(), "Cookie should accept spaces in value");
        assertEquals("exam-ple.com", cookie.getDomain().orElse(null), "Cookie should extract domain with hyphens");
        assertEquals("/path with spaces", cookie.getPath().orElse(null), "Cookie should extract path with spaces");
    }


}
