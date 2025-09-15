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
import de.cuioss.http.security.exceptions.UrlSecurityException;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.validation.CharacterValidationStage;
import de.cuioss.http.security.validation.LengthValidationStage;
import de.cuioss.http.security.validation.NormalizationStage;
import de.cuioss.http.security.validation.PatternMatchingStage;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Objects;

/**
 * Sequential validation pipeline specifically for HTTP request/response body content.
 *
 * <h3>Validation Sequence</h3>
 * <ol>
 *   <li><strong>Length Validation</strong> - Enforces maximum body size limits</li>
 *   <li><strong>Character Validation</strong> - Validates allowed character sets</li>
 *   <li><strong>Normalization</strong> - Content normalization and security checks</li>
 *   <li><strong>Pattern Matching</strong> - Detects injection attacks and malicious content</li>
 * </ol>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Sequential Execution</strong> - Each stage processes the output of the previous stage</li>
 *   <li><strong>Early Termination</strong> - Pipeline stops on first security violation</li>
 *   <li><strong>Content Aware</strong> - Handles various body content types and encodings</li>
 *   <li><strong>Immutable</strong> - Thread-safe pipeline instance</li>
 * </ul>
 *
 * <h3>HTTP Body Security</h3>
 * <ul>
 *   <li><strong>Size Limits</strong> - Prevents body-based DoS attacks via maxBodySize</li>
 *   <li><strong>Content Validation</strong> - Validates against RFC-compliant character sets</li>
 *   <li><strong>XSS Prevention</strong> - Detects cross-site scripting and HTTP-based attack patterns</li>
 *   <li><strong>Content Type Filtering</strong> - Supports allowed/blocked content type lists</li>
 *   <li><strong>Encoding Safety</strong> - Handles Unicode normalization and dangerous characters</li>
 * </ul>
 *
 * <h3>Content Type Support</h3>
 * <ul>
 *   <li><strong>Text Content</strong> - JSON, XML, plain text, form data</li>
 *   <li><strong>Structured Data</strong> - Validates structure and content simultaneously</li>
 *   <li><strong>Binary Safety</strong> - Handles binary content within character validation limits</li>
 *   <li><strong>Encoding Normalization</strong> - Unicode normalization for security</li>
 * </ul>
 *
 * <h3>Usage Example</h3>
 * <pre>
 * SecurityConfiguration config = SecurityConfiguration.builder()
 *     .maxBodySize(5 * 1024 * 1024) // 5MB limit
 *     .allowedContentTypes(Set.of("application/json", "text/plain"))
 *     .build();
 * SecurityEventCounter counter = new SecurityEventCounter();
 *
 * HTTPBodyValidationPipeline pipeline = new HTTPBodyValidationPipeline(config, counter);
 *
 * try {
 *     String safeBody = pipeline.validate(requestBody);
 *     // Process safe body content
 * } catch (UrlSecurityException e) {
 *     // Handle security violation
 *     log.warn("Body validation failed: {}", e.getMessage());
 *     throw new BadRequestException("Invalid request body", e);
 * }
 * </pre>
 *
 * <h3>Performance Considerations</h3>
 * <ul>
 *   <li><strong>Early Length Check</strong> - Rejects oversized content before processing</li>
 *   <li><strong>Streaming Support</strong> - Can validate large bodies efficiently</li>
 *   <li><strong>Pattern Optimization</strong> - Uses compiled patterns for fast detection</li>
 *   <li><strong>Memory Efficient</strong> - No unnecessary string copying during validation</li>
 * </ul>
 *
 * Implements: Task P4 from HTTP verification specification
 *
 * @since 2.5
 */
@EqualsAndHashCode
@ToString
public final class HTTPBodyValidationPipeline implements HttpSecurityValidator {

    private final List<HttpSecurityValidator> stages;
    private final SecurityEventCounter eventCounter;
    private final ValidationType validationType;

    /**
     * Creates a new HTTP body validation pipeline with the specified configuration.
     *
     * @param config The security configuration to use
     * @param eventCounter The counter for tracking security events
     * @throws NullPointerException if config or eventCounter is null
     */
    public HTTPBodyValidationPipeline(SecurityConfiguration config,
            SecurityEventCounter eventCounter) {
        this.eventCounter = Objects.requireNonNull(eventCounter, "EventCounter must not be null");
        Objects.requireNonNull(config, "Config must not be null");

        this.validationType = ValidationType.BODY;

        // Create validation stages in the correct order for HTTP body content
        // Note: Body content typically doesn't need URL decoding, similar to headers
        this.stages = List.of(
                new LengthValidationStage(config, ValidationType.BODY),
                new CharacterValidationStage(config, ValidationType.BODY),
                new NormalizationStage(config, ValidationType.BODY),
                new PatternMatchingStage(config, ValidationType.BODY)
        );
    }

    @Override
    public String validate(@Nullable String value) throws UrlSecurityException {
        String result = value;

        // Sequential execution with early termination
        for (HttpSecurityValidator stage : stages) {
            try {
                result = stage.validate(result);
            } catch (UrlSecurityException e) {
                // Track security event
                eventCounter.increment(e.getFailureType());

                // Re-throw with correct validation type
                throw UrlSecurityException.builder()
                        .failureType(e.getFailureType())
                        .validationType(validationType)
                        .originalInput(value) // Use original input, not current result
                        .sanitizedInput(e.getSanitizedInput().orElse(null))
                        .detail(e.getDetail().orElse("Validation failed"))
                        .cause(e.getCause())
                        .build();
            }
        }

        return result;
    }

    /**
     * Returns the validation type handled by this pipeline.
     *
     * @return ValidationType.BODY
     */
    public ValidationType getValidationType() {
        return validationType;
    }

    /**
     * Returns the list of validation stages in execution order.
     *
     * @return An immutable list of validation stages
     */
    public List<HttpSecurityValidator> getStages() {
        return stages;
    }

    /**
     * Returns the event counter used by this pipeline.
     *
     * @return The security event counter
     */
    public SecurityEventCounter getEventCounter() {
        return eventCounter;
    }
}