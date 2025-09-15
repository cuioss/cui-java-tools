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

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * A common wrapper around {@link HttpClient} that provides a builder for collecting
 * HTTP request attributes and methods for executing HTTP requests.
 * It provides a consistent way to configure and execute HTTP requests with proper
 * SSL context handling and timeout configuration.
 * <strong>Contract:</strong>
 * <ul>
 *   <li>The URI/URL must be valid and convertible to a URL. Invalid URIs will cause
 *       an {@link IllegalStateException} during build.</li>
 *   <li>For HTTPS connections, a valid {@link SSLContext} is required. If not explicitly
 *       provided, one will be automatically created during build.</li>
 * </ul>
 *
 * Use the builder to create instances of this class:
 * <pre>
 * HttpHandler handler = HttpHandler.builder()
 *     .uri("https://example.com/api")
 *     .connectionTimeoutSeconds(5)
 *     .readTimeoutSeconds(10)
 *     .build();
 * </pre>
 */
@EqualsAndHashCode
@ToString
@Builder(builderClassName = "HttpHandlerBuilder", access = AccessLevel.PRIVATE)
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class HttpHandler {

    private static final CuiLogger LOGGER = new CuiLogger(HttpHandler.class);
    public static final int DEFAULT_CONNECTION_TIMEOUT_SECONDS = 10;
    public static final int DEFAULT_READ_TIMEOUT_SECONDS = 10;

    /**
     * The URI to be used for HTTP requests.
     */
    @Getter
    private final URI uri;

    /**
     * The URL representation of the URI.
     */
    @Getter
    private final URL url;

    /**
     * The SSL context to be used for HTTPS connections.
     */
    @Getter
    private final SSLContext sslContext;

    /**
     * The connection timeout in seconds for HTTP requests.
     */
    @Getter
    private final int connectionTimeoutSeconds;

    /**
     * The read timeout in seconds for HTTP requests.
     */
    @Getter
    private final int readTimeoutSeconds;


    /**
     * Returns a new builder for creating a {@link HttpHandler} instance.
     *
     * @return A new builder instance.
     */
    public static HttpHandlerBuilder builder() {
        return new HttpHandlerBuilder();
    }

    /**
     * Creates a pre-configured {@link HttpRequest.Builder} for the URI contained in this handler.
     * The builder is configured with the read timeout from this handler.
     *
     * @return A pre-configured {@link HttpRequest.Builder}
     */
    public HttpRequest.Builder requestBuilder() {
        return HttpRequest.newBuilder()
                .uri(uri)
                .timeout(Duration.ofSeconds(readTimeoutSeconds));
    }

    /**
     * Creates a pre-configured {@link HttpHandlerBuilder} with the same configuration as this handler.
     * The builder is configured with the connection timeout, read timeout and sslContext from this handler.
     *
     * <p>This method allows creating a new builder based on the current handler's configuration,
     * which can be used to create a new handler with modified URL.</p>
     *
     * @return A pre-configured {@link HttpHandlerBuilder} with the same timeouts as this handler
     */
    public HttpHandlerBuilder asBuilder() {
        return builder()
                .connectionTimeoutSeconds(connectionTimeoutSeconds)
                .readTimeoutSeconds(readTimeoutSeconds)
                .sslContext(sslContext);
    }

    /**
     * Pings the URI using the HEAD method and returns the HTTP status code.
     *
     * @return The HTTP status code family, or {@link HttpStatusFamily#UNKNOWN} if an error occurred
     */
    // HttpClient implements AutoCloseable in Java 17 but doesn't need to be closed
    @SuppressWarnings("try")
    public HttpStatusFamily pingHead() {
        return pingWithMethod("HEAD", HttpRequest.BodyPublishers.noBody());
    }

    /**
     * Pings the URI using the GET method and returns the HTTP status code.
     *
     * @return The HTTP status code family, or {@link HttpStatusFamily#UNKNOWN} if an error occurred
     */
    // HttpClient implements AutoCloseable in Java 17 but doesn't need to be closed
    @SuppressWarnings("try")
    public HttpStatusFamily pingGet() {
        return pingWithMethod("GET", HttpRequest.BodyPublishers.noBody());
    }

    /**
     * Pings the URI using the specified HTTP method and returns the HTTP status code.
     *
     * @param method The HTTP method to use (e.g., "HEAD", "GET")
     * @param bodyPublisher The body publisher to use for the request
     * @return The HTTP status code family, or {@link HttpStatusFamily#UNKNOWN} if an error occurred
     */
    // HttpClient implements AutoCloseable in Java 17 but doesn't need to be closed
    // cui-rewrite:disable CuiLogRecordPatternRecipe
    @SuppressWarnings("try")
    private HttpStatusFamily pingWithMethod(String method, HttpRequest.BodyPublisher bodyPublisher) {
        try {
            HttpClient httpClient = createHttpClient();
            HttpRequest request = requestBuilder()
                    .method(method, bodyPublisher)
                    .build();

            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            return HttpStatusFamily.fromStatusCode(response.statusCode());
        } catch (IOException e) {
            LOGGER.warn(e, "IO error while pinging URI %s: %s", uri, e.getMessage());
            return HttpStatusFamily.UNKNOWN;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while pinging URI %s: %s", uri, e.getMessage());
            return HttpStatusFamily.UNKNOWN;
        } catch (IllegalArgumentException | SecurityException e) {
            LOGGER.warn(e, "Error while pinging URI %s: %s", uri, e.getMessage());
            return HttpStatusFamily.UNKNOWN;
        }
    }

    /**
     * Creates an {@link HttpClient} with the configured SSL context and connection timeout.
     * This method can be used to get a pre-configured HttpClient for making HTTP requests.
     *
     * @return A configured {@link HttpClient} with the SSL context and connection timeout
     */
    public HttpClient createHttpClient() {
        HttpClient.Builder httpClientBuilder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(connectionTimeoutSeconds));

        // For HTTPS URIs, SSL context must be set
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            httpClientBuilder.sslContext(sslContext);
        }
        return httpClientBuilder.build();
    }

    /**
     * Builder for creating {@link HttpHandler} instances.
     */
    public static class HttpHandlerBuilder {
        private URI uri;
        private URL url;
        private String urlString;
        private SSLContext sslContext;
        private SecureSSLContextProvider secureSSLContextProvider;
        private Integer connectionTimeoutSeconds;
        private Integer readTimeoutSeconds;

        /**
         * Sets the URI as a string.
         *
         * @param uriString The string representation of the URI.
         *                  Must not be null or empty.
         * @return This builder instance.
         * @throws IllegalArgumentException if the URI string is null, empty, or malformed
         *                                  (thrown during the {@link #build()} method execution,
         *                                  not by this setter method)
         */
        public HttpHandlerBuilder uri(String uriString) {
            this.urlString = uriString;
            return this;
        }

        /**
         * Sets the URI directly.
         * <p>
         * Note: If both URI and URL are set, the URI takes precedence.
         * </p>
         *
         * @param uri The URI to be used for HTTP requests.
         *            Must not be null.
         * @return This builder instance.
         */
        public HttpHandlerBuilder uri(URI uri) {
            this.uri = uri;
            return this;
        }

        /**
         * Sets the URL as a string.
         * <p>
         * Note: This method is provided for backward compatibility.
         * Consider using {@link #uri(String)} instead.
         * </p>
         *
         * @param urlString The string representation of the URL.
         *                  Must not be null or empty.
         * @return This builder instance.
         * @throws IllegalArgumentException if the URL string is null, empty, or malformed
         *                                  (thrown during the {@link #build()} method execution,
         *                                  not by this setter method)
         */
        public HttpHandlerBuilder url(String urlString) {
            this.urlString = urlString;
            return this;
        }

        /**
         * Sets the URL directly.
         * <p>
         * Note: This method is provided for backward compatibility.
         * Consider using {@link #uri(URI)} instead.
         * </p>
         * <p>
         * If both URI and URL are set, the URI takes precedence.
         * </p>
         *
         * @param url The URL to be used for HTTP requests.
         *            Must not be null.
         * @return This builder instance.
         */
        public HttpHandlerBuilder url(URL url) {
            this.url = url;
            return this;
        }

        /**
         * Sets the SSL context to use for HTTPS connections.
         * <p>
         * If not set, a default secure SSL context will be created.
         * </p>
         *
         * @param sslContext The SSL context to use.
         * @return This builder instance.
         */
        public HttpHandlerBuilder sslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        /**
         * Sets the TLS versions configuration.
         *
         * @param secureSSLContextProvider The TLS versions configuration to use.
         * @return This builder instance.
         */
        public HttpHandlerBuilder tlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            this.secureSSLContextProvider = secureSSLContextProvider;
            return this;
        }

        /**
         * Sets the connection timeout in seconds for HTTP requests.
         * <p>
         * If not set, a default timeout of 10 seconds will be used.
         * </p>
         *
         * @param connectionTimeoutSeconds The connection timeout in seconds.
         *                                Must be positive.
         * @return This builder instance.
         */
        public HttpHandlerBuilder connectionTimeoutSeconds(int connectionTimeoutSeconds) {
            this.connectionTimeoutSeconds = connectionTimeoutSeconds;
            return this;
        }

        /**
         * Sets the read timeout in seconds for HTTP requests.
         * <p>
         * If not set, a default timeout of 10 seconds will be used.
         * </p>
         *
         * @param readTimeoutSeconds The read timeout in seconds.
         *                          Must be positive.
         * @return This builder instance.
         */
        public HttpHandlerBuilder readTimeoutSeconds(int readTimeoutSeconds) {
            this.readTimeoutSeconds = readTimeoutSeconds;
            return this;
        }

        /**
         * Builds a new {@link HttpHandler} instance with the configured parameters.
         *
         * @return A new {@link HttpHandler} instance.
         * @throws IllegalArgumentException If any parameter is invalid.
         */
        public HttpHandler build() {
            // Resolve the URI from the provided inputs
            resolveUri();

            // Validate connection timeout
            int actualConnectionTimeoutSeconds = connectionTimeoutSeconds != null ?
                    connectionTimeoutSeconds : DEFAULT_CONNECTION_TIMEOUT_SECONDS;
            if (actualConnectionTimeoutSeconds <= 0) {
                throw new IllegalArgumentException("Connection timeout must be positive");
            }

            // Validate read timeout
            int actualReadTimeoutSeconds = readTimeoutSeconds != null ?
                    readTimeoutSeconds : DEFAULT_READ_TIMEOUT_SECONDS;
            if (actualReadTimeoutSeconds <= 0) {
                throw new IllegalArgumentException("Read timeout must be positive");
            }

            // Convert the URI to a URL
            URL verifiedUrl;
            try {
                verifiedUrl = uri.toURL();
            } catch (MalformedURLException e) {
                throw new IllegalStateException("Failed to convert URI to URL: " + uri, e);
            }

            // Create a secure SSL context if the URI uses HTTPS or if explicitly provided
            SSLContext secureContext = null;
            if ("https".equalsIgnoreCase(uri.getScheme()) || secureSSLContextProvider != null || sslContext != null) {
                SecureSSLContextProvider actualSecureSSLContextProvider = secureSSLContextProvider != null ?
                        secureSSLContextProvider : new SecureSSLContextProvider();
                secureContext = actualSecureSSLContextProvider.getOrCreateSecureSSLContext(sslContext);
            }

            return new HttpHandler(uri, verifiedUrl, secureContext, actualConnectionTimeoutSeconds, actualReadTimeoutSeconds);
        }

        /**
         * Resolves the URI from the provided inputs.
         * Priority: 1. uri, 2. url, 3. urlString
         */
        private void resolveUri() {
            // If URI is already set, use it
            if (uri != null) {
                return;
            }

            // If URL is set, convert it to URI
            if (url != null) {
                try {
                    uri = url.toURI();
                    return;
                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException("Invalid URL: " + url, e);
                }
            }

            // If urlString is set, convert it to URI
            if (!MoreStrings.isBlank(urlString)) {
                // Check if the URL has a scheme, if not prepend https://
                String urlToUse = urlString;
                if (!urlToUse.matches("^[a-zA-Z][a-zA-Z0-9+.-]*:.*")) {
                    LOGGER.debug(() -> "URL missing scheme, prepending https:// to %s".formatted(urlString));
                    urlToUse = "https://" + urlToUse;
                }

                uri = URI.create(urlToUse);
                return;
            }

            // If we get here, no valid URI source was provided
            throw new IllegalArgumentException("URI must not be null or empty.");
        }
    }
}
