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
 * Sequential validation pipeline specifically for URL path components.
 *
 * <h3>Validation Sequence</h3>
 * <ol>
 *   <li><strong>Length Validation</strong> - Enforces maximum path length limits</li>
 *   <li><strong>Character Validation</strong> - Validates RFC 3986 path characters</li>
 *   <li><strong>Decoding</strong> - URL decodes with security checks</li>
 *   <li><strong>Normalization</strong> - Path normalization and traversal detection</li>
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
 * URLPathValidationPipeline pipeline = new URLPathValidationPipeline(config, counter);
 *
 * try {
 *     String safePath = pipeline.validate("/api/users/123");
 *     // Use safePath for processing
 * } catch (UrlSecurityException e) {
 *     // Handle security violation
 *     log.warn("Path validation failed: {}", e.getMessage());
 * }
 * </pre>
 *
 * Implements: Task P1 from HTTP verification specification
 *
 * @since 2.5
 */
@EqualsAndHashCode
@ToString
public final class URLPathValidationPipeline implements HttpSecurityValidator {

    private final List<HttpSecurityValidator> stages;
    private final SecurityEventCounter eventCounter;
    private final ValidationType validationType = ValidationType.URL_PATH;

    /**
     * Creates a new URL path validation pipeline with the specified configuration.
     *
     * @param config The security configuration to use
     * @param eventCounter The counter for tracking security events
     * @throws NullPointerException if config or eventCounter is null
     */
    public URLPathValidationPipeline(SecurityConfiguration config,
            SecurityEventCounter eventCounter) {
        this.eventCounter = Objects.requireNonNull(eventCounter, "EventCounter must not be null");
        Objects.requireNonNull(config, "Config must not be null");

        // Create validation stages in the correct order
        // CRITICAL: PatternMatchingStage must run BEFORE normalization to catch all traversal patterns
        this.stages = List.of(
                new LengthValidationStage(config, ValidationType.URL_PATH),
                new CharacterValidationStage(config, ValidationType.URL_PATH),
                new PatternMatchingStage(config, ValidationType.URL_PATH), // MOVED HERE - before decoding/normalization
                new DecodingStage(config, ValidationType.URL_PATH),
                new NormalizationStage(config, ValidationType.URL_PATH),
                new PatternMatchingStage(config, ValidationType.URL_PATH)  // DUPLICATE - after normalization for defense in depth
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
     * @return ValidationType.URL_PATH
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