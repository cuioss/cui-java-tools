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
package de.cuioss.http.security.pipeline;

import de.cuioss.http.security.config.SecurityConfiguration;
import de.cuioss.http.security.core.HttpSecurityValidator;
import de.cuioss.http.security.core.ValidationType;
import de.cuioss.http.security.monitoring.SecurityEventCounter;

import java.util.Objects;

/**
 * Factory class for creating HTTP security validation pipelines.
 *
 * <p>This factory provides centralized creation of all HTTP security validation pipelines
 * with consistent configuration and monitoring. It ensures proper pipeline selection
 * based on the type of HTTP component being validated and provides convenient factory
 * methods for common use cases.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Centralized Creation</strong> - Single point for pipeline instantiation</li>
 *   <li><strong>Type Safety</strong> - Compile-time verification of pipeline types</li>
 *   <li><strong>Configuration Consistency</strong> - Ensures all pipelines use same config</li>
 *   <li><strong>Monitoring Integration</strong> - Unified event tracking across pipelines</li>
 * </ul>
 *
 * <h3>Supported Pipeline Types</h3>
 * <ul>
 *   <li><strong>URL Path Validation</strong> - For URL path segments and components</li>
 *   <li><strong>URL Parameter Validation</strong> - For query parameter values</li>
 *   <li><strong>HTTP Header Validation</strong> - For header names and values</li>
 *   <li><strong>HTTP Body Validation</strong> - For request/response body content</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * SecurityConfiguration config = SecurityConfiguration.defaults();
 * SecurityEventCounter counter = new SecurityEventCounter();
 *
 * // Create specific pipeline types
 * HttpSecurityValidator pathValidator = PipelineFactory.createUrlPathPipeline(config, counter);
 * HttpSecurityValidator paramValidator = PipelineFactory.createUrlParameterPipeline(config, counter);
 * HttpSecurityValidator headerNameValidator = PipelineFactory.createHeaderNamePipeline(config, counter);
 * HttpSecurityValidator headerValueValidator = PipelineFactory.createHeaderValuePipeline(config, counter);
 * HttpSecurityValidator bodyValidator = PipelineFactory.createBodyPipeline(config, counter);
 *
 * // Generic factory method based on validation type
 * HttpSecurityValidator validator = PipelineFactory.createPipeline(ValidationType.URL_PATH, config, counter);
 * </pre>
 *
 * <h3>Factory Method Benefits</h3>
 * <ul>
 *   <li><strong>Type Safety</strong> - Prevents incorrect ValidationType for header pipelines</li>
 *   <li><strong>Simplified API</strong> - Clear method names for common use cases</li>
 *   <li><strong>Future Extensibility</strong> - Easy to add new pipeline types</li>
 *   <li><strong>Configuration Validation</strong> - Ensures proper pipeline setup</li>
 * </ul>
 *
 * <h3>Thread Safety</h3>
 * <p>This factory class is stateless and thread-safe. All factory methods can be called
 * concurrently from multiple threads. The created pipelines are also thread-safe and
 * immutable.</p>
 *
 * Implements: Task P5 from HTTP verification specification
 *
 * @since 2.5
 */
public final class PipelineFactory {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private PipelineFactory() {
        // Utility class
    }

    /**
     * Creates a URL path validation pipeline for validating URL path components.
     *
     * <p>This pipeline validates URL path segments for security threats including:</p>
     * <ul>
     *   <li>Path traversal attacks (../)</li>
     *   <li>Directory escape attempts</li>
     *   <li>Encoded path traversal patterns</li>
     *   <li>Suspicious path patterns</li>
     *   <li>Invalid URL encoding</li>
     * </ul>
     *
     * @param config The security configuration to use
     * @param eventCounter The event counter for tracking security violations
     * @return A configured URL path validation pipeline
     * @throws NullPointerException if config or eventCounter is null
     */
    public static HttpSecurityValidator createUrlPathPipeline(
            SecurityConfiguration config, SecurityEventCounter eventCounter) {
        return new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Creates a URL parameter validation pipeline for validating query parameter values.
     *
     * <p>This pipeline validates URL parameter values for HTTP-layer security threats including:</p>
     * <ul>
     *   <li>XSS attack patterns</li>
     *   <li>Path traversal attempts</li>
     *   <li>Invalid URL encoding</li>
     *   <li>Parameter-based attacks</li>
     *   <li>Character encoding attacks</li>
     * </ul>
     *
     * @param config The security configuration to use
     * @param eventCounter The event counter for tracking security violations
     * @return A configured URL parameter validation pipeline
     * @throws NullPointerException if config or eventCounter is null
     */
    public static HttpSecurityValidator createUrlParameterPipeline(
            SecurityConfiguration config, SecurityEventCounter eventCounter) {
        return new URLParameterValidationPipeline(config, eventCounter);
    }

    /**
     * Creates an HTTP header name validation pipeline.
     *
     * <p>This pipeline validates HTTP header names according to RFC 7230 specifications
     * and checks for:</p>
     * <ul>
     *   <li>Invalid header name characters</li>
     *   <li>Header injection attempts</li>
     *   <li>CRLF injection patterns</li>
     *   <li>Suspicious header names</li>
     * </ul>
     *
     * @param config The security configuration to use
     * @param eventCounter The event counter for tracking security violations
     * @return A configured HTTP header name validation pipeline
     * @throws NullPointerException if config or eventCounter is null
     */
    public static HttpSecurityValidator createHeaderNamePipeline(
            SecurityConfiguration config, SecurityEventCounter eventCounter) {
        return new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);
    }

    /**
     * Creates an HTTP header value validation pipeline.
     *
     * <p>This pipeline validates HTTP header values according to RFC 7230 specifications
     * and checks for:</p>
     * <ul>
     *   <li>Invalid header value characters</li>
     *   <li>Header injection attempts</li>
     *   <li>CRLF injection patterns</li>
     *   <li>Malicious header content</li>
     * </ul>
     *
     * @param config The security configuration to use
     * @param eventCounter The event counter for tracking security violations
     * @return A configured HTTP header value validation pipeline
     * @throws NullPointerException if config or eventCounter is null
     */
    public static HttpSecurityValidator createHeaderValuePipeline(
            SecurityConfiguration config, SecurityEventCounter eventCounter) {
        return new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);
    }

    /**
     * Creates an HTTP body content validation pipeline.
     *
     * <p>This pipeline validates HTTP request/response body content for HTTP-layer
     * security threats including:</p>
     * <ul>
     *   <li>XSS attack patterns</li>
     *   <li>Character encoding attacks</li>
     *   <li>Body-based DoS attacks</li>
     *   <li>Content structure violations</li>
     *   <li>HTTP protocol attacks</li>
     * </ul>
     *
     * @param config The security configuration to use
     * @param eventCounter The event counter for tracking security violations
     * @return A configured HTTP body validation pipeline
     * @throws NullPointerException if config or eventCounter is null
     */
    public static HttpSecurityValidator createBodyPipeline(
            SecurityConfiguration config, SecurityEventCounter eventCounter) {
        return new HTTPBodyValidationPipeline(config, eventCounter);
    }

    /**
     * Generic factory method that creates the appropriate validation pipeline
     * based on the specified validation type.
     *
     * <p>This method provides a unified interface for creating any type of validation
     * pipeline. It's particularly useful when the pipeline type is determined at runtime.</p>
     *
     * <h3>Supported Validation Types</h3>
     * <ul>
     *   <li><strong>URL_PATH</strong> - Creates URLPathValidationPipeline</li>
     *   <li><strong>PARAMETER_VALUE</strong> - Creates URLParameterValidationPipeline</li>
     *   <li><strong>HEADER_NAME</strong> - Creates HTTPHeaderValidationPipeline for names</li>
     *   <li><strong>HEADER_VALUE</strong> - Creates HTTPHeaderValidationPipeline for values</li>
     *   <li><strong>BODY</strong> - Creates HTTPBodyValidationPipeline</li>
     * </ul>
     *
     * @param validationType The type of validation pipeline to create
     * @param config The security configuration to use
     * @param eventCounter The event counter for tracking security violations
     * @return A configured validation pipeline of the appropriate type
     * @throws NullPointerException if any parameter is null
     * @throws IllegalArgumentException if validationType is not supported or invalid
     */
    public static HttpSecurityValidator createPipeline(
            ValidationType validationType, SecurityConfiguration config, SecurityEventCounter eventCounter) {

        Objects.requireNonNull(validationType, "ValidationType must not be null");
        Objects.requireNonNull(config, "Config must not be null");
        Objects.requireNonNull(eventCounter, "EventCounter must not be null");

        return switch (validationType) {
            case URL_PATH -> createUrlPathPipeline(config, eventCounter);
            case PARAMETER_VALUE -> createUrlParameterPipeline(config, eventCounter);
            case HEADER_NAME -> createHeaderNamePipeline(config, eventCounter);
            case HEADER_VALUE -> createHeaderValuePipeline(config, eventCounter);
            case BODY -> createBodyPipeline(config, eventCounter);
            case PARAMETER_NAME -> throw new IllegalArgumentException(
                    "PARAMETER_NAME validation is not supported. Use PARAMETER_VALUE for parameter validation.");
            case COOKIE_NAME, COOKIE_VALUE -> throw new IllegalArgumentException(
                    """
                    Cookie validation pipelines are not yet implemented. \
                    Supported types: URL_PATH, PARAMETER_VALUE, HEADER_NAME, HEADER_VALUE, BODY""");
        };
    }

    /**
     * Creates multiple validation pipelines for common HTTP component validation scenarios.
     *
     * <p>This convenience method creates a set of commonly used pipelines with shared
     * configuration and monitoring. This is useful for applications that need to validate
     * multiple types of HTTP components.</p>
     *
     * @param config The security configuration to use for all pipelines
     * @param eventCounter The event counter for tracking security violations across all pipelines
     * @return A {@link PipelineSet} containing commonly used validation pipelines
     * @throws NullPointerException if config or eventCounter is null
     */
    public static PipelineSet createCommonPipelines(SecurityConfiguration config, SecurityEventCounter eventCounter) {
        Objects.requireNonNull(config, "Config must not be null");
        Objects.requireNonNull(eventCounter, "EventCounter must not be null");

        return new PipelineSet(
                createUrlPathPipeline(config, eventCounter),
                createUrlParameterPipeline(config, eventCounter),
                createHeaderNamePipeline(config, eventCounter),
                createHeaderValuePipeline(config, eventCounter),
                createBodyPipeline(config, eventCounter)
        );
    }

    /**
     * A record containing commonly used HTTP validation pipelines.
     *
     * <p>This immutable record provides convenient access to all the main pipeline types
     * with consistent configuration and monitoring.</p>
     *
     * @param urlPathPipeline Pipeline for validating URL path components
     * @param urlParameterPipeline Pipeline for validating URL parameter values
     * @param headerNamePipeline Pipeline for validating HTTP header names
     * @param headerValuePipeline Pipeline for validating HTTP header values
     * @param bodyPipeline Pipeline for validating HTTP body content
     */
    public record PipelineSet(
    HttpSecurityValidator urlPathPipeline,
    HttpSecurityValidator urlParameterPipeline,
    HttpSecurityValidator headerNamePipeline,
    HttpSecurityValidator headerValuePipeline,
    HttpSecurityValidator bodyPipeline
    ) {
        public PipelineSet {
            Objects.requireNonNull(urlPathPipeline, "urlPathPipeline must not be null");
            Objects.requireNonNull(urlParameterPipeline, "urlParameterPipeline must not be null");
            Objects.requireNonNull(headerNamePipeline, "headerNamePipeline must not be null");
            Objects.requireNonNull(headerValuePipeline, "headerValuePipeline must not be null");
            Objects.requireNonNull(bodyPipeline, "bodyPipeline must not be null");
        }
    }
}