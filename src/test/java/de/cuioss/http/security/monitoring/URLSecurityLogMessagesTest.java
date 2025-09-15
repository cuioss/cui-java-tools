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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link URLSecurityLogMessages}
 */
class URLSecurityLogMessagesTest {

    private static final String EXPECTED_PREFIX = "URLSecurity";

    @Test
    @DisplayName("WARN messages should have correct identifiers and format")
    void warnMessagesShouldHaveCorrectIdentifiers() {
        // Test PATH_TRAVERSAL_DETECTED
        LogRecord pathTraversalMsg = URLSecurityLogMessages.WARN.PATH_TRAVERSAL_DETECTED;
        assertEquals(301, pathTraversalMsg.getIdentifier());
        assertTrue(pathTraversalMsg.getTemplate().contains("Path traversal attempt"));
        String formatted = pathTraversalMsg.format("../../../etc/passwd");
        assertTrue(formatted.contains(EXPECTED_PREFIX + "-301"));
        assertTrue(formatted.contains("../../../etc/passwd"));

        // Test DOUBLE_ENCODING_DETECTED
        LogRecord doubleEncodingMsg = URLSecurityLogMessages.WARN.DOUBLE_ENCODING_DETECTED;
        assertEquals(302, doubleEncodingMsg.getIdentifier());
        assertTrue(doubleEncodingMsg.getTemplate().contains("Double encoding attack"));
        String formatted2 = doubleEncodingMsg.format("%2525");
        assertTrue(formatted2.contains(EXPECTED_PREFIX + "-302"));
        assertTrue(formatted2.contains("%2525"));

        // Test UNICODE_ATTACK_DETECTED
        LogRecord unicodeMsg = URLSecurityLogMessages.WARN.UNICODE_ATTACK_DETECTED;
        assertEquals(303, unicodeMsg.getIdentifier());
        assertTrue(unicodeMsg.getTemplate().contains("Unicode normalization attack"));
        String formatted3 = unicodeMsg.format("ﬁle", "file");
        assertTrue(formatted3.contains(EXPECTED_PREFIX + "-303"));
        assertTrue(formatted3.contains("ﬁle"));
        assertTrue(formatted3.contains("file"));

        // Test NULL_BYTE_DETECTED
        LogRecord nullByteMsg = URLSecurityLogMessages.WARN.NULL_BYTE_DETECTED;
        assertEquals(304, nullByteMsg.getIdentifier());
        assertTrue(nullByteMsg.getTemplate().contains("Null byte injection"));

        // Test CONTROL_CHARACTERS_DETECTED
        LogRecord controlCharMsg = URLSecurityLogMessages.WARN.CONTROL_CHARACTERS_DETECTED;
        assertEquals(305, controlCharMsg.getIdentifier());
        assertTrue(controlCharMsg.getTemplate().contains("Control character injection"));

        // Test LENGTH_LIMIT_EXCEEDED
        LogRecord lengthLimitMsg = URLSecurityLogMessages.WARN.LENGTH_LIMIT_EXCEEDED;
        assertEquals(306, lengthLimitMsg.getIdentifier());
        String formatted4 = lengthLimitMsg.format("PATH", "5000", "4096");
        assertTrue(formatted4.contains("PATH"));
        assertTrue(formatted4.contains("5000"));
        assertTrue(formatted4.contains("4096"));

        // Test SUSPICIOUS_PATTERN_DETECTED
        LogRecord suspiciousMsg = URLSecurityLogMessages.WARN.SUSPICIOUS_PATTERN_DETECTED;
        assertEquals(307, suspiciousMsg.getIdentifier());
        String formatted5 = suspiciousMsg.format("URL", "admin", "/admin/secret");
        assertTrue(formatted5.contains("URL"));
        assertTrue(formatted5.contains("admin"));

        // Test ATTACK_SIGNATURE_DETECTED
        LogRecord attackSigMsg = URLSecurityLogMessages.WARN.ATTACK_SIGNATURE_DETECTED;
        assertEquals(308, attackSigMsg.getIdentifier());

        // Test MALFORMED_INPUT_DETECTED
        LogRecord malformedMsg = URLSecurityLogMessages.WARN.MALFORMED_INPUT_DETECTED;
        assertEquals(309, malformedMsg.getIdentifier());

        // Test RATE_LIMIT_EXCEEDED
        LogRecord rateLimitMsg = URLSecurityLogMessages.WARN.RATE_LIMIT_EXCEEDED;
        assertEquals(310, rateLimitMsg.getIdentifier());
    }

    @Test
    @DisplayName("ERROR messages should have correct identifiers and format")
    void errorMessagesShouldHaveCorrectIdentifiers() {
        // Test VALIDATION_FAILED
        LogRecord validationFailedMsg = URLSecurityLogMessages.ERROR.VALIDATION_FAILED;
        assertEquals(401, validationFailedMsg.getIdentifier());
        assertTrue(validationFailedMsg.getTemplate().contains("URL validation failed"));
        String formatted = validationFailedMsg.format("PATH_TRAVERSAL_DETECTED", "/api/../admin");
        assertTrue(formatted.contains(EXPECTED_PREFIX + "-401"));
        assertTrue(formatted.contains("PATH_TRAVERSAL_DETECTED"));
        assertTrue(formatted.contains("/api/../admin"));

        // Test VALIDATOR_CONFIG_ERROR
        LogRecord configErrorMsg = URLSecurityLogMessages.ERROR.VALIDATOR_CONFIG_ERROR;
        assertEquals(402, configErrorMsg.getIdentifier());
        assertTrue(configErrorMsg.getTemplate().contains("configuration error"));

        // Test PIPELINE_EXECUTION_ERROR
        LogRecord pipelineErrorMsg = URLSecurityLogMessages.ERROR.PIPELINE_EXECUTION_ERROR;
        assertEquals(403, pipelineErrorMsg.getIdentifier());
        assertTrue(pipelineErrorMsg.getTemplate().contains("pipeline execution failed"));

        // Test SECURITY_SYSTEM_FAILURE
        LogRecord systemFailureMsg = URLSecurityLogMessages.ERROR.SECURITY_SYSTEM_FAILURE;
        assertEquals(404, systemFailureMsg.getIdentifier());
        assertTrue(systemFailureMsg.getTemplate().contains("Critical security system failure"));

        // Test EVENT_COUNTER_OVERFLOW
        LogRecord counterOverflowMsg = URLSecurityLogMessages.ERROR.EVENT_COUNTER_OVERFLOW;
        assertEquals(405, counterOverflowMsg.getIdentifier());
        assertTrue(counterOverflowMsg.getTemplate().contains("counter overflow"));
    }

    @Test
    @DisplayName("INFO messages should have correct identifiers and format")
    void infoMessagesShouldHaveCorrectIdentifiers() {
        // Test VALIDATION_ENABLED
        LogRecord validationEnabledMsg = URLSecurityLogMessages.INFO.VALIDATION_ENABLED;
        assertEquals(201, validationEnabledMsg.getIdentifier());
        assertTrue(validationEnabledMsg.getTemplate().contains("Security validation enabled"));
        String formatted = validationEnabledMsg.format("PATH", "strict");
        assertTrue(formatted.contains(EXPECTED_PREFIX + "-201"));
        assertTrue(formatted.contains("PATH"));
        assertTrue(formatted.contains("strict"));

        // Test CONFIG_LOADED
        LogRecord configLoadedMsg = URLSecurityLogMessages.INFO.CONFIG_LOADED;
        assertEquals(202, configLoadedMsg.getIdentifier());
        assertTrue(configLoadedMsg.getTemplate().contains("configuration loaded"));

        // Test VALIDATION_PASSED
        LogRecord validationPassedMsg = URLSecurityLogMessages.INFO.VALIDATION_PASSED;
        assertEquals(203, validationPassedMsg.getIdentifier());
        assertTrue(validationPassedMsg.getTemplate().contains("validation passed"));

        // Test SYSTEM_INITIALIZED
        LogRecord systemInitMsg = URLSecurityLogMessages.INFO.SYSTEM_INITIALIZED;
        assertEquals(204, systemInitMsg.getIdentifier());
        assertTrue(systemInitMsg.getTemplate().contains("system initialized"));

        // Test METRICS_SUMMARY
        LogRecord metricsMsg = URLSecurityLogMessages.INFO.METRICS_SUMMARY;
        assertEquals(205, metricsMsg.getIdentifier());
        assertTrue(metricsMsg.getTemplate().contains("Security metrics"));
        String formatted2 = metricsMsg.format("1h", "1000", "5");
        assertTrue(formatted2.contains("1h"));
        assertTrue(formatted2.contains("1000"));
        assertTrue(formatted2.contains("5"));
    }

    @Test
    @DisplayName("DEBUG messages should have correct identifiers and format")
    void debugMessagesShouldHaveCorrectIdentifiers() {
        // Test VALIDATION_STAGE
        LogRecord validationStageMsg = URLSecurityLogMessages.DEBUG.VALIDATION_STAGE;
        assertEquals(101, validationStageMsg.getIdentifier());
        assertTrue(validationStageMsg.getTemplate().contains("Validation stage executed"));
        String formatted = validationStageMsg.format("DecodingStage", "passed", "0.5");
        assertTrue(formatted.contains(EXPECTED_PREFIX + "-101"));
        assertTrue(formatted.contains("DecodingStage"));
        assertTrue(formatted.contains("passed"));
        assertTrue(formatted.contains("0.5"));

        // Test VALIDATION_STEP
        LogRecord validationStepMsg = URLSecurityLogMessages.DEBUG.VALIDATION_STEP;
        assertEquals(102, validationStepMsg.getIdentifier());
        assertTrue(validationStepMsg.getTemplate().contains("Validation step"));

        // Test PATTERN_MATCH
        LogRecord patternMatchMsg = URLSecurityLogMessages.DEBUG.PATTERN_MATCH;
        assertEquals(103, patternMatchMsg.getIdentifier());
        assertTrue(patternMatchMsg.getTemplate().contains("Pattern matching"));

        // Test CHARACTER_VALIDATION
        LogRecord charValidationMsg = URLSecurityLogMessages.DEBUG.CHARACTER_VALIDATION;
        assertEquals(104, charValidationMsg.getIdentifier());
        assertTrue(charValidationMsg.getTemplate().contains("Character validation"));

        // Test URL_DECODING
        LogRecord urlDecodingMsg = URLSecurityLogMessages.DEBUG.URL_DECODING;
        assertEquals(105, urlDecodingMsg.getIdentifier());
        assertTrue(urlDecodingMsg.getTemplate().contains("URL decoding"));
        String formatted2 = urlDecodingMsg.format("%2F", "/", "percent");
        assertTrue(formatted2.contains("%2F"));
        assertTrue(formatted2.contains("/"));
        assertTrue(formatted2.contains("percent"));

        // Test CONFIG_PARAMETER
        LogRecord configParamMsg = URLSecurityLogMessages.DEBUG.CONFIG_PARAMETER;
        assertEquals(106, configParamMsg.getIdentifier());
        assertTrue(configParamMsg.getTemplate().contains("Configuration parameter"));
    }

    @Test
    @DisplayName("All message identifiers should be unique")
    void allMessageIdentifiersShouldBeUnique() {
        // Collect all identifiers
        Set<Integer> identifiers = new HashSet<>();

        // WARN messages (301-310)
        identifiers.add(URLSecurityLogMessages.WARN.PATH_TRAVERSAL_DETECTED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.WARN.DOUBLE_ENCODING_DETECTED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.WARN.UNICODE_ATTACK_DETECTED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.WARN.NULL_BYTE_DETECTED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.WARN.CONTROL_CHARACTERS_DETECTED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.WARN.LENGTH_LIMIT_EXCEEDED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.WARN.SUSPICIOUS_PATTERN_DETECTED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.WARN.ATTACK_SIGNATURE_DETECTED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.WARN.MALFORMED_INPUT_DETECTED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.WARN.RATE_LIMIT_EXCEEDED.getIdentifier());

        // ERROR messages (401-405)
        identifiers.add(URLSecurityLogMessages.ERROR.VALIDATION_FAILED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.ERROR.VALIDATOR_CONFIG_ERROR.getIdentifier());
        identifiers.add(URLSecurityLogMessages.ERROR.PIPELINE_EXECUTION_ERROR.getIdentifier());
        identifiers.add(URLSecurityLogMessages.ERROR.SECURITY_SYSTEM_FAILURE.getIdentifier());
        identifiers.add(URLSecurityLogMessages.ERROR.EVENT_COUNTER_OVERFLOW.getIdentifier());

        // INFO messages (201-205)
        identifiers.add(URLSecurityLogMessages.INFO.VALIDATION_ENABLED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.INFO.CONFIG_LOADED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.INFO.VALIDATION_PASSED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.INFO.SYSTEM_INITIALIZED.getIdentifier());
        identifiers.add(URLSecurityLogMessages.INFO.METRICS_SUMMARY.getIdentifier());

        // DEBUG messages (101-106)
        identifiers.add(URLSecurityLogMessages.DEBUG.VALIDATION_STAGE.getIdentifier());
        identifiers.add(URLSecurityLogMessages.DEBUG.VALIDATION_STEP.getIdentifier());
        identifiers.add(URLSecurityLogMessages.DEBUG.PATTERN_MATCH.getIdentifier());
        identifiers.add(URLSecurityLogMessages.DEBUG.CHARACTER_VALIDATION.getIdentifier());
        identifiers.add(URLSecurityLogMessages.DEBUG.URL_DECODING.getIdentifier());
        identifiers.add(URLSecurityLogMessages.DEBUG.CONFIG_PARAMETER.getIdentifier());

        // Should have 26 unique identifiers
        assertEquals(26, identifiers.size(), "All message identifiers must be unique");
    }

    @Test
    @DisplayName("All messages should have URLSecurity prefix")
    void allMessagesShouldHaveCorrectPrefix() {
        // Sample from each category to verify prefix
        assertTrue(URLSecurityLogMessages.WARN.PATH_TRAVERSAL_DETECTED.format("test")
                .startsWith(EXPECTED_PREFIX + "-"));
        assertTrue(URLSecurityLogMessages.ERROR.VALIDATION_FAILED.format("type", "input")
                .startsWith(EXPECTED_PREFIX + "-"));
        assertTrue(URLSecurityLogMessages.INFO.VALIDATION_ENABLED.format("type", "level")
                .startsWith(EXPECTED_PREFIX + "-"));
        assertTrue(URLSecurityLogMessages.DEBUG.VALIDATION_STAGE.format("stage", "status", "time")
                .startsWith(EXPECTED_PREFIX + "-"));
    }

    @Test
    @DisplayName("Messages should handle null parameters gracefully")
    void messagesShouldHandleNullParameters() {
        // Test with null parameters - should not throw exceptions
        assertDoesNotThrow(() -> {
            URLSecurityLogMessages.WARN.PATH_TRAVERSAL_DETECTED.format((Object) null);
        });

        assertDoesNotThrow(() -> {
            URLSecurityLogMessages.ERROR.VALIDATION_FAILED.format(null, null);
        });

        assertDoesNotThrow(() -> {
            URLSecurityLogMessages.INFO.METRICS_SUMMARY.format(null, null, null);
        });
    }

    @Test
    @DisplayName("Messages should handle empty parameters")
    void messagesShouldHandleEmptyParameters() {
        // Test with empty parameters
        String result1 = URLSecurityLogMessages.WARN.PATH_TRAVERSAL_DETECTED.format("");
        assertTrue(result1.contains(EXPECTED_PREFIX + "-301"));

        String result2 = URLSecurityLogMessages.ERROR.VALIDATION_FAILED.format("", "");
        assertTrue(result2.contains(EXPECTED_PREFIX + "-401"));

        String result3 = URLSecurityLogMessages.DEBUG.VALIDATION_STAGE.format("", "", "");
        assertTrue(result3.contains(EXPECTED_PREFIX + "-101"));
    }

    @Test
    @DisplayName("Message identifiers should follow conventions")
    void messageIdentifiersShouldFollowConventions() {
        // DEBUG messages should be 101-199
        assertTrue(URLSecurityLogMessages.DEBUG.VALIDATION_STAGE.getIdentifier() >= 101);
        assertTrue(URLSecurityLogMessages.DEBUG.CONFIG_PARAMETER.getIdentifier() <= 199);

        // INFO messages should be 201-299
        assertTrue(URLSecurityLogMessages.INFO.VALIDATION_ENABLED.getIdentifier() >= 201);
        assertTrue(URLSecurityLogMessages.INFO.METRICS_SUMMARY.getIdentifier() <= 299);

        // WARN messages should be 301-399
        assertTrue(URLSecurityLogMessages.WARN.PATH_TRAVERSAL_DETECTED.getIdentifier() >= 301);
        assertTrue(URLSecurityLogMessages.WARN.RATE_LIMIT_EXCEEDED.getIdentifier() <= 399);

        // ERROR messages should be 401-499
        assertTrue(URLSecurityLogMessages.ERROR.VALIDATION_FAILED.getIdentifier() >= 401);
        assertTrue(URLSecurityLogMessages.ERROR.EVENT_COUNTER_OVERFLOW.getIdentifier() <= 499);
    }

    @Test
    @DisplayName("Message templates should contain placeholders")
    void messageTemplatesShouldContainPlaceholders() {
        // Single parameter messages should have at least one placeholder
        assertTrue(URLSecurityLogMessages.WARN.PATH_TRAVERSAL_DETECTED.getTemplate().contains("{}"));

        // Multi-parameter messages should have multiple placeholders
        String unicodeTemplate = URLSecurityLogMessages.WARN.UNICODE_ATTACK_DETECTED.getTemplate();
        long placeholderCount = unicodeTemplate.chars().mapToObj(c -> (char) c)
                .filter(c -> c == '{').count();
        assertTrue(placeholderCount >= 2, "Unicode attack message should have at least 2 placeholders");

        // Complex messages should have appropriate number of placeholders
        String lengthTemplate = URLSecurityLogMessages.WARN.LENGTH_LIMIT_EXCEEDED.getTemplate();
        long lengthPlaceholders = lengthTemplate.chars().mapToObj(c -> (char) c)
                .filter(c -> c == '{').count();
        assertTrue(lengthPlaceholders >= 3, "Length limit message should have at least 3 placeholders");
    }

    @Test
    @DisplayName("Formatted messages should be parseable")
    void formattedMessagesShouldBeParseable() {
        // Test that formatted messages contain structured information
        String pathTraversalMsg = URLSecurityLogMessages.WARN.PATH_TRAVERSAL_DETECTED.format("../../../etc/passwd");

        // Should contain the identifier for parsing
        assertTrue(pathTraversalMsg.matches(".*URLSecurity-301:.*"));

        // Should contain the actual attack string
        assertTrue(pathTraversalMsg.contains("../../../etc/passwd"));

        // Test complex message
        String validationFailedMsg = URLSecurityLogMessages.ERROR.VALIDATION_FAILED.format(
                "PATH_TRAVERSAL_DETECTED", "/api/../admin");

        assertTrue(validationFailedMsg.matches(".*URLSecurity-401:.*"));
        assertTrue(validationFailedMsg.contains("PATH_TRAVERSAL_DETECTED"));
        assertTrue(validationFailedMsg.contains("/api/../admin"));
    }
}