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
package de.cuioss.http.security.database;

import de.cuioss.http.security.core.UrlSecurityFailureType;

/**
 * Represents a single attack test case containing the attack string, expected failure type,
 * and comprehensive documentation about the attack mechanics and detection rationale.
 *
 * <p>This record encapsulates all necessary information for security testing, providing
 * both the attack payload and the contextual information needed to understand why
 * the specific failure type is expected. This approach enables comprehensive security
 * validation while maintaining clear traceability of attack patterns.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Complete Test Context</strong> - Contains both attack and expected outcome</li>
 *   <li><strong>Educational Value</strong> - Descriptions explain attack mechanics and detection</li>
 *   <li><strong>Immutable Design</strong> - Thread-safe record for concurrent testing</li>
 *   <li><strong>Clear Documentation</strong> - Self-documenting test cases</li>
 * </ul>
 *
 * <h3>Usage Example</h3>
 * <pre>
 * AttackTestCase sqlInjection = new AttackTestCase(
 *     "' UNION SELECT 1,2,3--",
 *     UrlSecurityFailureType.SQL_INJECTION_DETECTED,
 *     "Classic UNION-based SQL injection attempting to extract data by appending a UNION SELECT statement to manipulate the original query structure",
 *     "The SQL_INJECTION_DETECTED failure type is expected because the pattern contains the SQL UNION keyword combined with comment syntax (--), which are clear indicators of SQL injection attempts"
 * );
 * </pre>
 *
 * @param attackString The malicious payload or attack pattern to be tested
 * @param expectedFailureType The expected UrlSecurityFailureType that should be detected
 * @param attackDescription Comprehensive explanation of what this attack attempts to accomplish and how it works
 * @param detectionRationale Detailed explanation of why the specific UrlSecurityFailureType is expected for this attack
 *
 * @since 2.5
 */
public record AttackTestCase(
String attackString,
UrlSecurityFailureType expectedFailureType,
String attackDescription,
String detectionRationale
) {

    /**
     * Creates a new AttackTestCase with validation of required fields.
     *
     * @param attackString The malicious payload or attack pattern (must not be null or blank)
     * @param expectedFailureType The expected failure type (must not be null)
     * @param attackDescription Comprehensive attack explanation (must not be null or blank)
     * @param detectionRationale Detailed detection explanation (must not be null or blank)
     *
     * @throws IllegalArgumentException if any parameter is null or if strings are blank
     */
    public AttackTestCase {
        if (attackString == null || attackString.isBlank()) {
            throw new IllegalArgumentException("Attack string must not be null or blank");
        }
        if (expectedFailureType == null) {
            throw new IllegalArgumentException("Expected failure type must not be null");
        }
        if (attackDescription == null || attackDescription.isBlank()) {
            throw new IllegalArgumentException("Attack description must not be null or blank");
        }
        if (detectionRationale == null || detectionRationale.isBlank()) {
            throw new IllegalArgumentException("Detection rationale must not be null or blank");
        }
    }

    /**
     * Returns a human-readable string representation containing all attack information.
     * This format is designed for use in parameterized test failure messages, providing
     * complete context when a test fails.
     *
     * @return Formatted string with attack details suitable for test output
     */
    @Override
    public String toString() {
        return "AttackTestCase[attackString='%s', expectedFailureType=%s, attackDescription='%s', detectionRationale='%s']".formatted(
                attackString, expectedFailureType, attackDescription, detectionRationale
        );
    }

    /**
     * Returns a compact summary of this attack test case for logging and debugging.
     *
     * @return Short description combining attack type and expected failure
     */
    public String getCompactSummary() {
        return "%s -> %s".formatted(
                attackString.length() > 50 ? attackString.substring(0, 47) + "..." : attackString,
                expectedFailureType
        );
    }
}