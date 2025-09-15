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
package de.cuioss.http.security.monitoring;

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;

/**
 * Structured log messages for HTTP security validation events.
 *
 * <p>This class provides predefined, structured log messages for all types of HTTP security
 * events that can occur during URL validation. It follows the CUI LogRecord pattern to ensure
 * consistent, parseable, and actionable security logs.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Structured Logging</strong> - All messages follow consistent format with identifiers</li>
 *   <li><strong>Security Focus</strong> - Messages designed for security monitoring and alerting</li>
 *   <li><strong>Actionable</strong> - Each message provides context needed for response</li>
 *   <li><strong>Standardized</strong> - Uses CUI LogRecord pattern for consistency</li>
 * </ul>
 *
 * <h3>Message Categories</h3>
 * <ul>
 *   <li><strong>WARN</strong> - Security violations that were blocked but indicate potential attacks</li>
 *   <li><strong>ERROR</strong> - Critical security failures or system errors during validation</li>
 *   <li><strong>INFO</strong> - Security-relevant events that don't indicate attacks</li>
 *   <li><strong>DEBUG</strong> - Detailed validation information for troubleshooting</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * // Log a path traversal attack
 * logger.warn(URLSecurityLogMessages.WARN.PATH_TRAVERSAL_DETECTED.format("../../../etc/passwd"));
 *
 * // Log a validation failure with details
 * logger.error(URLSecurityLogMessages.ERROR.VALIDATION_FAILED.format(
 *     "PATH_TRAVERSAL_DETECTED", "/api/../admin"));
 *
 * // Log configuration information
 * logger.info(URLSecurityLogMessages.INFO.VALIDATION_ENABLED.format("PATH", "strict"));
 *
 * // Log detailed validation steps
 * logger.debug(URLSecurityLogMessages.DEBUG.VALIDATION_STEP.format("DecodingStage", "url encoded"));
 * </pre>
 *
 * <h3>Message Format</h3>
 * <p>All messages follow the pattern: <code>URLSecurity-[ID]: [message with parameters]</code></p>
 * <p>This format enables easy parsing by log analysis tools and SIEM systems for security monitoring.</p>
 *
 * Implements: Task S2 from HTTP verification specification
 *
 * @since 2.5
 * @see LogRecord
 * @see LogRecordModel
 * @see SecurityEventCounter
 */
public final class URLSecurityLogMessages {

    /**
     * Log message prefix for all URL security related messages.
     */
    private static final String PREFIX = "URLSecurity";

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private URLSecurityLogMessages() {
        // Utility class - no instances
    }

    /**
     * Warning level messages for security violations that were detected and blocked.
     * These messages indicate potential attacks that should be monitored and may trigger alerts.
     */
    public static final class WARN {

        /**
         * Path traversal attack detected and blocked.
         * Parameters: [0] = the malicious input that was detected
         */
        public static final LogRecord PATH_TRAVERSAL_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(301)
                .template("Path traversal attempt detected and blocked: {}")
                .build();

        /**
         * Double encoding attack detected and blocked.
         * Parameters: [0] = the double-encoded input that was detected
         */
        public static final LogRecord DOUBLE_ENCODING_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(302)
                .template("Double encoding attack detected and blocked: {}")
                .build();

        /**
         * Unicode normalization attack detected and blocked.
         * Parameters: [0] = the Unicode input, [1] = normalized form
         */
        public static final LogRecord UNICODE_ATTACK_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(303)
                .template("Unicode normalization attack detected - Original: {}, Normalized: {}")
                .build();

        /**
         * Null byte injection attack detected and blocked.
         * Parameters: [0] = the input containing null bytes
         */
        public static final LogRecord NULL_BYTE_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(304)
                .template("Null byte injection detected and blocked: {}")
                .build();

        /**
         * Control character injection detected and blocked.
         * Parameters: [0] = the input containing control characters
         */
        public static final LogRecord CONTROL_CHARACTERS_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(305)
                .template("Control character injection detected and blocked: {}")
                .build();

        /**
         * Input length exceeded maximum allowed limits.
         * Parameters: [0] = validation type, [1] = actual length, [2] = maximum allowed
         */
        public static final LogRecord LENGTH_LIMIT_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(306)
                .template("{} length limit exceeded - Actual: {}, Maximum: {}")
                .build();

        /**
         * Suspicious pattern detected in input.
         * Parameters: [0] = validation type, [1] = detected pattern, [2] = input
         */
        public static final LogRecord SUSPICIOUS_PATTERN_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(307)
                .template("Suspicious pattern detected in {} - Pattern: {}, Input: {}")
                .build();

        /**
         * Known attack signature detected and blocked.
         * Parameters: [0] = signature type, [1] = input that matched
         */
        public static final LogRecord ATTACK_SIGNATURE_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(308)
                .template("Known attack signature detected - Type: {}, Input: {}")
                .build();

        /**
         * Malformed input structure detected.
         * Parameters: [0] = validation type, [1] = description of malformation
         */
        public static final LogRecord MALFORMED_INPUT_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(309)
                .template("Malformed {} input detected: {}")
                .build();

        /**
         * Rate limit exceeded for security violations.
         * Parameters: [0] = failure type, [1] = current count, [2] = time window
         */
        public static final LogRecord RATE_LIMIT_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(310)
                .template("Security violation rate limit exceeded - Type: {}, Count: {} in {}")
                .build();

        private WARN() {
            // Utility class - no instances
        }
    }

    /**
     * Error level messages for critical security failures or system errors during validation.
     * These messages indicate serious problems that require immediate attention.
     */
    public static final class ERROR {

        /**
         * URL validation failed due to security violation.
         * Parameters: [0] = failure type, [1] = input that failed validation
         */
        public static final LogRecord VALIDATION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(401)
                .template("URL validation failed - Failure: {}, Input: {}")
                .build();

        /**
         * Security validator configuration error.
         * Parameters: [0] = validator type, [1] = error description
         */
        public static final LogRecord VALIDATOR_CONFIG_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(402)
                .template("Security validator configuration error - Validator: {}, Error: {}")
                .build();

        /**
         * Security pipeline execution error.
         * Parameters: [0] = pipeline stage, [1] = error message
         */
        public static final LogRecord PIPELINE_EXECUTION_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(403)
                .template("Security pipeline execution failed - Stage: {}, Error: {}")
                .build();

        /**
         * Critical security system failure.
         * Parameters: [0] = system component, [1] = failure description
         */
        public static final LogRecord SECURITY_SYSTEM_FAILURE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(404)
                .template("Critical security system failure - Component: {}, Description: {}")
                .build();

        /**
         * Security event counter overflow.
         * Parameters: [0] = failure type, [1] = current count
         */
        public static final LogRecord EVENT_COUNTER_OVERFLOW = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(405)
                .template("Security event counter overflow - Type: {}, Count: {}")
                .build();

        private ERROR() {
            // Utility class - no instances
        }
    }

    /**
     * Info level messages for security-relevant events that don't indicate attacks.
     * These messages provide operational information about the security system.
     */
    public static final class INFO {

        /**
         * Security validation system enabled.
         * Parameters: [0] = validation type, [1] = security level
         */
        public static final LogRecord VALIDATION_ENABLED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(201)
                .template("Security validation enabled - Type: {}, Level: {}")
                .build();

        /**
         * Security configuration loaded successfully.
         * Parameters: [0] = configuration source, [1] = validator count
         */
        public static final LogRecord CONFIG_LOADED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(202)
                .template("Security configuration loaded - Source: {}, Validators: {}")
                .build();

        /**
         * Security validation passed successfully.
         * Parameters: [0] = validation type, [1] = input (truncated for safety)
         */
        public static final LogRecord VALIDATION_PASSED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(203)
                .template("Security validation passed - Type: {}, Input: {}")
                .build();

        /**
         * Security system initialized.
         * Parameters: [0] = system version, [1] = active validators
         */
        public static final LogRecord SYSTEM_INITIALIZED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(204)
                .template("Security system initialized - Version: {}, Validators: {}")
                .build();

        /**
         * Security metrics summary.
         * Parameters: [0] = time period, [1] = total validations, [2] = violations
         */
        public static final LogRecord METRICS_SUMMARY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(205)
                .template("Security metrics - Period: {}, Validations: {}, Violations: {}")
                .build();

        private INFO() {
            // Utility class - no instances
        }
    }

    /**
     * Debug level messages for detailed validation information used in troubleshooting.
     * These messages are verbose and intended for development and debugging purposes.
     */
    public static final class DEBUG {

        /**
         * Individual validation stage execution.
         * Parameters: [0] = stage name, [1] = input status, [2] = execution time (ms)
         */
        public static final LogRecord VALIDATION_STAGE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(101)
                .template("Validation stage executed - Stage: {}, Status: {}, Time: {}ms")
                .build();

        /**
         * Detailed validation step information.
         * Parameters: [0] = validator name, [1] = step description
         */
        public static final LogRecord VALIDATION_STEP = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(102)
                .template("Validation step - Validator: {}, Step: {}")
                .build();

        /**
         * Pattern matching debug information.
         * Parameters: [0] = pattern name, [1] = input sample, [2] = match result
         */
        public static final LogRecord PATTERN_MATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(103)
                .template("Pattern matching - Pattern: {}, Input: {}, Result: {}")
                .build();

        /**
         * Character validation debug information.
         * Parameters: [0] = character set, [1] = invalid characters found, [2] = position
         */
        public static final LogRecord CHARACTER_VALIDATION = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(104)
                .template("Character validation - Set: {}, Invalid: {}, Position: {}")
                .build();

        /**
         * URL decoding debug information.
         * Parameters: [0] = original input, [1] = decoded output, [2] = encoding type
         */
        public static final LogRecord URL_DECODING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(105)
                .template("URL decoding - Original: {}, Decoded: {}, Type: {}")
                .build();

        /**
         * Configuration parameter debug information.
         * Parameters: [0] = parameter name, [1] = parameter value, [2] = source
         */
        public static final LogRecord CONFIG_PARAMETER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(106)
                .template("Configuration parameter - Name: {}, Value: {}, Source: {}")
                .build();

        private DEBUG() {
            // Utility class - no instances
        }
    }
}