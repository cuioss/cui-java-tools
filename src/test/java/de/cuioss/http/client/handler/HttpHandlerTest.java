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
package de.cuioss.http.client.handler;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpRequest;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link HttpHandler}
 */
class HttpHandlerTest {

    private static final String VALID_URL = "https://example.com";
    private static final int CUSTOM_CONNECTION_TIMEOUT = 15;
    private static final int CUSTOM_READ_TIMEOUT = 20;

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build with URL string")
        void shouldBuildWithUrlString() {
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .build();

            assertNotNull(handler);
            assertEquals(VALID_URL, handler.getUrl().toString());
            assertEquals(URI.create(VALID_URL), handler.getUri());
            assertEquals(HttpHandler.DEFAULT_CONNECTION_TIMEOUT_SECONDS, handler.getConnectionTimeoutSeconds());
            assertEquals(HttpHandler.DEFAULT_READ_TIMEOUT_SECONDS, handler.getReadTimeoutSeconds());
        }

        @Test
        @DisplayName("Should build with URL object")
        void shouldBuildWithUrlObject() throws Exception {
            URL url = URI.create(VALID_URL).toURL();
            HttpHandler handler = HttpHandler.builder()
                    .url(url)
                    .build();

            assertNotNull(handler);
            assertEquals(url, handler.getUrl());
            assertEquals(url.toURI(), handler.getUri());
        }

        @Test
        @DisplayName("Should build with URI string")
        void shouldBuildWithUriString() {
            HttpHandler handler = HttpHandler.builder()
                    .uri(VALID_URL)
                    .build();

            assertNotNull(handler);
            assertEquals(VALID_URL, handler.getUrl().toString());
            assertEquals(URI.create(VALID_URL), handler.getUri());
            assertEquals(HttpHandler.DEFAULT_CONNECTION_TIMEOUT_SECONDS, handler.getConnectionTimeoutSeconds());
            assertEquals(HttpHandler.DEFAULT_READ_TIMEOUT_SECONDS, handler.getReadTimeoutSeconds());
        }

        @Test
        @DisplayName("Should build with URI object")
        void shouldBuildWithUriObject() {
            URI uri = URI.create(VALID_URL);
            HttpHandler handler = HttpHandler.builder()
                    .uri(uri)
                    .build();

            assertNotNull(handler);
            assertEquals(uri, handler.getUri());
            assertEquals(VALID_URL, handler.getUrl().toString());
        }

        @Test
        @DisplayName("Should build with custom timeouts")
        void shouldBuildWithCustomTimeouts() {
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .connectionTimeoutSeconds(CUSTOM_CONNECTION_TIMEOUT)
                    .readTimeoutSeconds(CUSTOM_READ_TIMEOUT)
                    .build();

            assertNotNull(handler);
            assertEquals(CUSTOM_CONNECTION_TIMEOUT, handler.getConnectionTimeoutSeconds());
            assertEquals(CUSTOM_READ_TIMEOUT, handler.getReadTimeoutSeconds());
        }

        @Test
        @DisplayName("Should build with SSL context")
        void shouldBuildWithSslContext() throws Exception {
            SSLContext sslContext = SSLContext.getDefault();
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .sslContext(sslContext)
                    .build();

            assertNotNull(handler);
            assertNotNull(handler.getSslContext());
        }

        @Test
        @DisplayName("Should build with SecureSSLContextProvider")
        void shouldBuildWithSecureSSLContextProvider() {
            SecureSSLContextProvider provider = new SecureSSLContextProvider();
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .tlsVersions(provider)
                    .build();

            assertNotNull(handler);
            assertNotNull(handler.getSslContext());
        }

        @Test
        @DisplayName("Should prepend https:// to URL without scheme")
        void shouldPrependHttpsToUrlWithoutScheme() {
            String urlWithoutScheme = "example.com";
            HttpHandler handler = HttpHandler.builder()
                    .url(urlWithoutScheme)
                    .build();

            assertNotNull(handler);
            assertEquals("https://example.com", handler.getUrl().toString());
            assertEquals(URI.create("https://example.com"), handler.getUri());

            // Note: We're not testing the log message here as it's an implementation detail
            // and the test framework might have issues with capturing it
        }

        @Test
        @DisplayName("Should throw exception for null URL/URI")
        void shouldThrowExceptionForNullUrl() {
            var builder = HttpHandler.builder();
            var exception = assertThrows(IllegalArgumentException.class, builder::build);

            assertEquals("URI must not be null or empty.", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception for empty URL")
        void shouldThrowExceptionForEmptyUrl() {
            HttpHandler.HttpHandlerBuilder url = HttpHandler.builder().url("");
            var exception = assertThrows(IllegalArgumentException.class, url::build);

            assertEquals("URI must not be null or empty.", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception for invalid URL")
        void shouldThrowExceptionForInvalidUrl() {
            // Use a URL with illegal characters in the host part
            var url = HttpHandler.builder().url("http://invalid url with spaces.com");
            var exception = assertThrows(IllegalArgumentException.class, url::build);

            // Just verify it's an IllegalArgumentException with the invalid URL in the message
            assertTrue(exception.getMessage().contains("http://invalid url with spaces.com"));
        }

        @Test
        @DisplayName("Should throw exception for negative connection timeout")
        void shouldThrowExceptionForNegativeConnectionTimeout() {
            var builder = HttpHandler.builder().url(VALID_URL).connectionTimeoutSeconds(-1);
            var exception = assertThrows(IllegalArgumentException.class, builder::build);

            assertEquals("Connection timeout must be positive", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception for zero connection timeout")
        void shouldThrowExceptionForZeroConnectionTimeout() {
            var builder = HttpHandler.builder().url(VALID_URL).connectionTimeoutSeconds(0);
            var exception = assertThrows(IllegalArgumentException.class, builder::build);

            assertEquals("Connection timeout must be positive", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception for negative read timeout")
        void shouldThrowExceptionForNegativeReadTimeout() {
            var builder = HttpHandler.builder().url(VALID_URL).readTimeoutSeconds(-1);
            var exception = assertThrows(IllegalArgumentException.class, builder::build);

            assertEquals("Read timeout must be positive", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception for zero read timeout")
        void shouldThrowExceptionForZeroReadTimeout() {
            var builder = HttpHandler.builder().url(VALID_URL).readTimeoutSeconds(0);
            var exception = assertThrows(IllegalArgumentException.class, builder::build);

            assertEquals("Read timeout must be positive", exception.getMessage());
        }

        @Test
        @DisplayName("Should automatically create SSL context for HTTPS URLs")
        void shouldAutomaticallyCreateSslContextForHttpsUrls() {
            HttpHandler handler = HttpHandler.builder()
                    .url("https://example.com")
                    .build();

            assertNotNull(handler);
            assertNotNull(handler.getSslContext(), "SSL context should be automatically created for HTTPS URLs");
        }

        @Test
        @DisplayName("Should not create SSL context for HTTP URLs if not explicitly provided")
        void shouldNotCreateSslContextForHttpUrls() {
            HttpHandler handler = HttpHandler.builder()
                    .url("http://example.com")
                    .build();

            assertNotNull(handler);
            assertNull(handler.getSslContext(), "SSL context should not be created for HTTP URLs if not explicitly provided");
        }

        @Test
        @DisplayName("URI should take precedence over URL when both are set")
        void uriShouldTakePrecedenceOverUrl() throws Exception {
            URI uri = URI.create("https://example.org");
            URL url = URI.create("https://example.com").toURL();

            HttpHandler handler = HttpHandler.builder()
                    .url(url)
                    .uri(uri)
                    .build();

            assertNotNull(handler);
            assertEquals(uri, handler.getUri());
            assertEquals("https://example.org", handler.getUrl().toString());
        }
    }

    @Nested
    @DisplayName("Request Builder Tests")
    class RequestBuilderTests {

        @Test
        @DisplayName("Should create request builder with correct URI")
        void shouldCreateRequestBuilderWithCorrectUri() {
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .build();

            HttpRequest.Builder builder = handler.requestBuilder();

            assertNotNull(builder);

            // Build a request to check the URI
            HttpRequest request = builder.GET().build();
            assertEquals(URI.create(VALID_URL), request.uri());
        }

        @Test
        @DisplayName("Should create request builder with correct timeout")
        void shouldCreateRequestBuilderWithCorrectTimeout() {
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .readTimeoutSeconds(CUSTOM_READ_TIMEOUT)
                    .build();

            HttpRequest.Builder builder = handler.requestBuilder();

            assertNotNull(builder);

            // Build a request to check the timeout
            HttpRequest request = builder.GET().build();
            assertTrue(request.timeout().isPresent());
            assertEquals(Duration.ofSeconds(CUSTOM_READ_TIMEOUT), request.timeout().get());
        }
    }

    @Nested
    @DisplayName("Ping Tests")
    class PingTests {

        // Note: These tests don't actually make HTTP requests
        // They just verify the method signatures and error handling
        // Real HTTP requests would require mocking or integration tests

        @Test
        @DisplayName("pingHead should return UNKNOWN for unreachable URL")
        void pingHeadShouldReturnUnknownForUnreachableUrl() {
            HttpHandler handler = HttpHandler.builder()
                    .url("https://non-existent-domain-12345.example")
                    .build();

            HttpStatusFamily statusCode = handler.pingHead();
            assertEquals(HttpStatusFamily.UNKNOWN, statusCode);
        }

        @Test
        @DisplayName("pingGet should return UNKNOWN for unreachable URL")
        void pingGetShouldReturnUnknownForUnreachableUrl() {
            HttpHandler handler = HttpHandler.builder()
                    .url("https://non-existent-domain-12345.example")
                    .build();

            HttpStatusFamily statusCode = handler.pingGet();
            assertEquals(HttpStatusFamily.UNKNOWN, statusCode);
        }

        @Test
        @DisplayName("Should have SSL context for HTTPS URLs")
        void shouldHaveSslContextForHttpsUrls() {
            // This test verifies that the SSL context is always created for HTTPS URLs
            // which ensures that the exception in createHttpClient will never be thrown
            // in normal operation
            HttpHandler handler = HttpHandler.builder()
                    .url("https://example.com")
                    .build();

            assertNotNull(handler.getSslContext(),
                    "SSL context should be automatically created for HTTPS URLs to prevent exceptions in createHttpClient");
        }
    }

    @Nested
    @DisplayName("URL/URI Conversion Tests")
    class UrlUriConversionTests {

        @Test
        @DisplayName("getUrl should return URL representation of URI")
        void getUrlShouldReturnUrlRepresentationOfUri() {
            URI uri = URI.create(VALID_URL);
            HttpHandler handler = HttpHandler.builder()
                    .uri(uri)
                    .build();

            URL url = handler.getUrl();
            assertNotNull(url);
            assertEquals(VALID_URL, url.toString());
        }

        @Test
        @DisplayName("build should throw IllegalStateException for invalid URI")
        void buildShouldThrowIllegalStateExceptionForInvalidUri() throws Exception {
            // Create a URI that can't be converted to a valid URL
            URI invalidUri = new URI("urn:isbn:0451450523"); // URN that can't be converted to URL
            HttpHandler.HttpHandlerBuilder builder = HttpHandler.builder()
                    .uri(invalidUri);
            // The build method should throw an IllegalStateException when an invalid URI is provided
            IllegalStateException exception = assertThrows(IllegalStateException.class, builder::build);

            assertTrue(exception.getMessage().startsWith("Failed to convert URI to URL: urn:isbn:0451450523"));
        }
    }

    @Nested
    @DisplayName("asBuilder Tests")
    class AsBuilderTests {

        @Test
        @DisplayName("asBuilder should return non-null builder")
        void asBuilderShouldReturnNonNullBuilder() {
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .build();

            HttpHandler.HttpHandlerBuilder builder = handler.asBuilder();
            assertNotNull(builder, "asBuilder should return a non-null builder");
        }

        @Test
        @DisplayName("asBuilder should preserve timeouts")
        void asBuilderShouldPreserveTimeouts() {
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .connectionTimeoutSeconds(CUSTOM_CONNECTION_TIMEOUT)
                    .readTimeoutSeconds(CUSTOM_READ_TIMEOUT)
                    .build();

            HttpHandler newHandler = handler.asBuilder()
                    .url(VALID_URL) // Need to set URL again as asBuilder doesn't copy it
                    .build();
            assertEquals(CUSTOM_CONNECTION_TIMEOUT, newHandler.getConnectionTimeoutSeconds(),
                    "The new handler should have the same connection timeout as the original");
            assertEquals(CUSTOM_READ_TIMEOUT, newHandler.getReadTimeoutSeconds(),
                    "The new handler should have the same read timeout as the original");
        }

        @Test
        @DisplayName("asBuilder should preserve SSL context")
        void asBuilderShouldPreserveSslContext() throws Exception {
            SSLContext sslContext = SSLContext.getDefault();
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .sslContext(sslContext)
                    .build();

            HttpHandler newHandler = handler.asBuilder()
                    .url(VALID_URL) // Need to set URL again as asBuilder doesn't copy it
                    .build();
            assertNotNull(newHandler.getSslContext(), "The new handler should have an SSL context");
            // Note: We can't directly compare SSL contexts as they might be wrapped
        }

        @Test
        @DisplayName("asBuilder should allow changing URL")
        void asBuilderShouldAllowChangingUrl() {
            HttpHandler handler = HttpHandler.builder()
                    .url(VALID_URL)
                    .connectionTimeoutSeconds(CUSTOM_CONNECTION_TIMEOUT)
                    .readTimeoutSeconds(CUSTOM_READ_TIMEOUT)
                    .build();

            String newUrl = "https://example.org";
            HttpHandler newHandler = handler.asBuilder()
                    .url(newUrl)
                    .build();

            assertEquals(URI.create(newUrl), newHandler.getUri(),
                    "The new handler should have the updated URI");
            assertEquals(CUSTOM_CONNECTION_TIMEOUT, newHandler.getConnectionTimeoutSeconds(),
                    "The new handler should preserve the original connection timeout");
            assertEquals(CUSTOM_READ_TIMEOUT, newHandler.getReadTimeoutSeconds(),
                    "The new handler should preserve the original read timeout");
        }
    }
}
