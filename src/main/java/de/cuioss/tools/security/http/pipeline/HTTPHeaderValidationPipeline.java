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
package de.cuioss.tools.security.http.pipeline;

import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.HttpSecurityValidator;
import de.cuioss.tools.security.http.core.ValidationType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.validation.CharacterValidationStage;
import de.cuioss.tools.security.http.validation.LengthValidationStage;
import de.cuioss.tools.security.http.validation.NormalizationStage;
import de.cuioss.tools.security.http.validation.PatternMatchingStage;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.util.List;
import java.util.Objects;

/**
 * Sequential validation pipeline specifically for HTTP header components.
 * 
 * <h3>Validation Sequence</h3>
 * <ol>
 *   <li><strong>Length Validation</strong> - Enforces maximum header length limits</li>
 *   <li><strong>Character Validation</strong> - Validates RFC 7230 header characters</li>
 *   <li><strong>Normalization</strong> - Header normalization and security checks</li>
 *   <li><strong>Pattern Matching</strong> - Detects injection attacks and suspicious patterns</li>
 * </ol>
 * 
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Sequential Execution</strong> - Each stage processes the output of the previous stage</li>
 *   <li><strong>Early Termination</strong> - Pipeline stops on first security violation</li>
 *   <li><strong>Security First</strong> - Validates before any transformation</li>
 *   <li><strong>Immutable</strong> - Thread-safe pipeline instance</li>
 * </ul>
 * 
 * <h3>HTTP Header Security</h3>
 * <ul>
 *   <li><strong>Header Injection Prevention</strong> - Detects CRLF injection attempts</li>
 *   <li><strong>RFC 7230 Compliance</strong> - Enforces HTTP header character restrictions</li>
 *   <li><strong>Length Limits</strong> - Prevents header-based DoS attacks</li>
 *   <li><strong>Pattern Detection</strong> - Identifies malicious header values</li>
 * </ul>
 * 
 * <h3>Usage Example</h3>
 * <pre>
 * SecurityConfiguration config = SecurityConfiguration.defaults();
 * SecurityEventCounter counter = new SecurityEventCounter();
 * 
 * HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, counter);
 * 
 * try {
 *     String safeHeader = pipeline.validate("Bearer eyJhbGciOiJIUzI1NiJ9...");
 *     // Use safeHeader for processing
 * } catch (UrlSecurityException e) {
 *     // Handle security violation
 *     log.warn("Header validation failed: {}", e.getMessage());
 * }
 * </pre>
 * 
 * Implements: Task P3 from HTTP verification specification
 * 
 * @since 2.5
 */
@EqualsAndHashCode
@ToString
public final class HTTPHeaderValidationPipeline implements HttpSecurityValidator {

    private final @NonNull List<HttpSecurityValidator> stages;
    private final @NonNull SecurityEventCounter eventCounter;
    private final @NonNull ValidationType validationType;

    /**
     * Creates a new HTTP header validation pipeline with the specified configuration.
     * The pipeline can be configured for either header names or header values.
     * 
     * @param config The security configuration to use
     * @param eventCounter The counter for tracking security events
     * @param validationType The type of header component to validate (HEADER_NAME or HEADER_VALUE)
     * @throws NullPointerException if config, eventCounter, or validationType is null
     * @throws IllegalArgumentException if validationType is not a header type
     */
    public HTTPHeaderValidationPipeline(@NonNull SecurityConfiguration config,
            @NonNull SecurityEventCounter eventCounter,
            @NonNull ValidationType validationType) {
        this.eventCounter = Objects.requireNonNull(eventCounter, "EventCounter must not be null");
        Objects.requireNonNull(config, "Config must not be null");
        Objects.requireNonNull(validationType, "ValidationType must not be null");

        if (!validationType.isHeader()) {
            throw new IllegalArgumentException("ValidationType must be a header type, got: " + validationType);
        }

        this.validationType = validationType;

        // Create validation stages in the correct order for HTTP headers
        // Note: Headers typically don't need URL decoding, so we skip DecodingStage
        this.stages = List.of(
                new LengthValidationStage(config, validationType),
                new CharacterValidationStage(config, validationType),
                new NormalizationStage(config, validationType),
                new PatternMatchingStage(config, validationType)
        );
    }

    @Override
    public String validate(String value) throws UrlSecurityException {
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
     * @return The configured header validation type (HEADER_NAME or HEADER_VALUE)
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