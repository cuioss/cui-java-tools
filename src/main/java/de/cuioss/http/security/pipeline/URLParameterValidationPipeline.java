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
import de.cuioss.http.security.validation.*;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Objects;

/**
 * Sequential validation pipeline specifically for URL parameter components.
 *
 * <h3>Validation Sequence</h3>
 * <ol>
 *   <li><strong>Length Validation</strong> - Enforces maximum parameter length limits</li>
 *   <li><strong>Character Validation</strong> - Validates RFC 3986 query characters</li>
 *   <li><strong>Decoding</strong> - URL decodes with security checks</li>
 *   <li><strong>Normalization</strong> - Parameter normalization and security checks</li>
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
 * <h3>Usage Example</h3>
 * <pre>
 * SecurityConfiguration config = SecurityConfiguration.defaults();
 * SecurityEventCounter counter = new SecurityEventCounter();
 *
 * URLParameterValidationPipeline pipeline = new URLParameterValidationPipeline(config, counter);
 *
 * try {
 *     String safeParam = pipeline.validate("user_id=123");
 *     // Use safeParam for processing
 * } catch (UrlSecurityException e) {
 *     // Handle security violation
 *     log.warn("Parameter validation failed: {}", e.getMessage());
 * }
 * </pre>
 *
 * Implements: Task P2 from HTTP verification specification
 *
 * @since 2.5
 */
@EqualsAndHashCode
@ToString
public final class URLParameterValidationPipeline implements HttpSecurityValidator {

    private final List<HttpSecurityValidator> stages;
    private final SecurityEventCounter eventCounter;
    private final ValidationType validationType = ValidationType.PARAMETER_VALUE;

    /**
     * Creates a new URL parameter validation pipeline with the specified configuration.
     *
     * @param config The security configuration to use
     * @param eventCounter The counter for tracking security events
     * @throws NullPointerException if config or eventCounter is null
     */
    public URLParameterValidationPipeline(SecurityConfiguration config,
            SecurityEventCounter eventCounter) {
        this.eventCounter = Objects.requireNonNull(eventCounter, "EventCounter must not be null");
        Objects.requireNonNull(config, "Config must not be null");

        // Create validation stages in the correct order for URL parameters
        this.stages = List.of(
                new LengthValidationStage(config, ValidationType.PARAMETER_VALUE),
                new CharacterValidationStage(config, ValidationType.PARAMETER_VALUE),
                new DecodingStage(config, ValidationType.PARAMETER_VALUE),
                new NormalizationStage(config, ValidationType.PARAMETER_VALUE),
                new PatternMatchingStage(config, ValidationType.PARAMETER_VALUE)
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
     * @return ValidationType.PARAMETER_VALUE
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