/**
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
package de.cuioss.tools.net.http;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link SecureSSLContextProvider} class.
 */
@DisplayName("Tests SecureSSLContextProvider functionality")
class SecureSSLContextProviderTest {

    @Test
    @DisplayName("Should define correct TLS version constants")
    void shouldDefineCorrectConstants() {
        assertEquals("TLSv1.2", SecureSSLContextProvider.TLS_V1_2);
        assertEquals("TLSv1.3", SecureSSLContextProvider.TLS_V1_3);
        assertEquals("TLS", SecureSSLContextProvider.TLS);
        assertEquals("TLSv1.0", SecureSSLContextProvider.TLS_V1_0);
        assertEquals("TLSv1.1", SecureSSLContextProvider.TLS_V1_1);
        assertEquals("SSLv3", SecureSSLContextProvider.SSL_V3);
        assertEquals(SecureSSLContextProvider.TLS_V1_2, SecureSSLContextProvider.DEFAULT_TLS_VERSION);
    }

    @Test
    @DisplayName("Should have correct allowed TLS versions")
    void shouldHaveCorrectAllowedVersions() {
        assertEquals(3, SecureSSLContextProvider.ALLOWED_TLS_VERSIONS.size());
        assertTrue(SecureSSLContextProvider.ALLOWED_TLS_VERSIONS.contains(SecureSSLContextProvider.TLS_V1_2));
        assertTrue(SecureSSLContextProvider.ALLOWED_TLS_VERSIONS.contains(SecureSSLContextProvider.TLS_V1_3));
        assertTrue(SecureSSLContextProvider.ALLOWED_TLS_VERSIONS.contains(SecureSSLContextProvider.TLS));
    }

    @Test
    @DisplayName("Should have correct forbidden TLS versions")
    void shouldHaveCorrectForbiddenVersions() {
        assertEquals(3, SecureSSLContextProvider.FORBIDDEN_TLS_VERSIONS.size());
        assertTrue(SecureSSLContextProvider.FORBIDDEN_TLS_VERSIONS.contains(SecureSSLContextProvider.TLS_V1_0));
        assertTrue(SecureSSLContextProvider.FORBIDDEN_TLS_VERSIONS.contains(SecureSSLContextProvider.TLS_V1_1));
        assertTrue(SecureSSLContextProvider.FORBIDDEN_TLS_VERSIONS.contains(SecureSSLContextProvider.SSL_V3));
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3", "TLS"})
    @DisplayName("Should identify secure TLS versions with default minimum (TLS 1.2)")
    void shouldIdentifySecureTlsVersionsWithDefaultMinimum(String protocol) {
        SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider();
        assertTrue(secureSSLContextProvider.isSecureTlsVersion(protocol));
        assertEquals(SecureSSLContextProvider.TLS_V1_2, secureSSLContextProvider.getMinimumTlsVersion());
    }

    @Test
    @DisplayName("Should identify secure TLS versions with TLS 1.3 as minimum")
    void shouldIdentifySecureTlsVersionsWithTls13Minimum() {
        SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider(SecureSSLContextProvider.TLS_V1_3);

        // TLS 1.3 and generic TLS should be secure
        assertTrue(secureSSLContextProvider.isSecureTlsVersion(SecureSSLContextProvider.TLS_V1_3));
        assertTrue(secureSSLContextProvider.isSecureTlsVersion(SecureSSLContextProvider.TLS));

        // TLS 1.2 should not be secure when minimum is TLS 1.3
        assertFalse(secureSSLContextProvider.isSecureTlsVersion(SecureSSLContextProvider.TLS_V1_2));

        assertEquals(SecureSSLContextProvider.TLS_V1_3, secureSSLContextProvider.getMinimumTlsVersion());
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2", "unknown"})
    @DisplayName("Should identify insecure TLS versions")
    void shouldIdentifyInsecureTlsVersions(String protocol) {
        SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider();
        assertFalse(secureSSLContextProvider.isSecureTlsVersion(protocol));
    }

    @Test
    @DisplayName("Should handle null protocol")
    void shouldHandleNullProtocol() {
        SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider();
        assertFalse(secureSSLContextProvider.isSecureTlsVersion(null));
    }

    @Test
    @DisplayName("Should have no overlap between allowed and forbidden versions")
    void shouldHaveNoOverlapBetweenAllowedAndForbidden() {
        for (String allowed : SecureSSLContextProvider.ALLOWED_TLS_VERSIONS) {
            assertFalse(SecureSSLContextProvider.FORBIDDEN_TLS_VERSIONS.contains(allowed),
                    "Protocol " + allowed + " should not be in both allowed and forbidden sets");
        }

        for (String forbidden : SecureSSLContextProvider.FORBIDDEN_TLS_VERSIONS) {
            assertFalse(SecureSSLContextProvider.ALLOWED_TLS_VERSIONS.contains(forbidden),
                    "Protocol " + forbidden + " should not be in both allowed and forbidden sets");
        }
    }

    @Test
    @DisplayName("Should create secure SSL context with default minimum")
    void shouldCreateSecureSSLContextWithDefaultMinimum() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        // When: Creating a secure SSL context with default minimum
        SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider();
        SSLContext sslContext = secureSSLContextProvider.createSecureSSLContext();

        // Then: The context should not be null
        assertNotNull(sslContext, "SSL context should not be null");

        // And: The protocol should be the default TLS version
        assertEquals(SecureSSLContextProvider.TLS_V1_2, sslContext.getProtocol(),
                "SSL context should use the default TLS version");
    }

    @Test
    @DisplayName("Should create secure SSL context with TLS 1.3 minimum")
    void shouldCreateSecureSSLContextWithTls13Minimum() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        // When: Creating a secure SSL context with TLS 1.3 minimum
        SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider(SecureSSLContextProvider.TLS_V1_3);
        SSLContext sslContext = secureSSLContextProvider.createSecureSSLContext();

        // Then: The context should not be null
        assertNotNull(sslContext, "SSL context should not be null");

        // And: The protocol should be TLS 1.3
        assertEquals(SecureSSLContextProvider.TLS_V1_3, sslContext.getProtocol(),
                "SSL context should use TLS 1.3");
    }

    @Test
    @DisplayName("Should throw exception for invalid minimum TLS version")
    void shouldThrowExceptionForInvalidMinimumTlsVersion() {
        assertThrows(IllegalArgumentException.class, () -> new SecureSSLContextProvider("invalid"));
    }

    @Test
    @DisplayName("Should validate and return secure SSLContext")
    void shouldValidateAndReturnSecureSSLContext() throws Exception {
        // Given: A SecureSSLContextProvider instance and a secure SSLContext
        SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider();
        SSLContext secureContext = SSLContext.getInstance(SecureSSLContextProvider.TLS_V1_2);
        secureContext.init(null, null, null);

        // When: Validating the secure context
        SSLContext result = secureSSLContextProvider.getOrCreateSecureSSLContext(secureContext);

        // Then: The same context should be returned
        assertSame(secureContext, result, "Should return the same context when it's secure");
    }

    @Test
    @DisplayName("Should create new SSLContext when provided one is insecure")
    void shouldCreateNewSSLContextWhenProvidedOneIsInsecure() throws Exception {
        // Given: A SecureSSLContextProvider instance with TLS 1.3 as minimum and a TLS 1.2 context
        SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider(SecureSSLContextProvider.TLS_V1_3);
        SSLContext insecureContext = SSLContext.getInstance(SecureSSLContextProvider.TLS_V1_2);
        insecureContext.init(null, null, null);

        // When: Validating the insecure context
        SSLContext result = secureSSLContextProvider.getOrCreateSecureSSLContext(insecureContext);

        // Then: A new context should be created
        assertNotSame(insecureContext, result, "Should create a new context when the provided one is insecure");
        assertEquals(SecureSSLContextProvider.TLS_V1_3, result.getProtocol(), "New context should use TLS 1.3");
    }

    @Test
    @DisplayName("Should create new SSLContext when null is provided")
    void shouldCreateNewSSLContextWhenNullIsProvided() {
        // Given: A SecureSSLContextProvider instance
        SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider();

        // When: Validating a null context
        SSLContext result = secureSSLContextProvider.getOrCreateSecureSSLContext(null);

        // Then: A new context should be created
        assertNotNull(result, "Should create a new context when null is provided");
        assertEquals(SecureSSLContextProvider.TLS_V1_2, result.getProtocol(), "New context should use TLS 1.2");
    }
}
