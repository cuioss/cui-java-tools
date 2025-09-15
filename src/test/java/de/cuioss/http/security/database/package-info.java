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

/**
 * Security Attack Database Framework for HTTP Vulnerability Testing.
 *
 * <p><strong>COMPREHENSIVE ATTACK DATABASE ARCHITECTURE:</strong> This package provides a structured
 * approach to security testing by organizing known attack patterns into well-documented databases.
 * Each database contains curated collections of real-world attack vectors with comprehensive
 * documentation, expected detection outcomes, and educational context.</p>
 *
 * <h2>Core Concepts</h2>
 *
 * <h3>1. Attack Test Cases</h3>
 * <p>The {@link de.cuioss.http.security.database.AttackTestCase} record serves as the foundation for all attack testing:</p>
 * <ul>
 *   <li><strong>Attack String</strong>: The actual malicious payload to be tested</li>
 *   <li><strong>Expected Failure Type</strong>: The specific {@link de.cuioss.http.security.core.UrlSecurityFailureType} expected</li>
 *   <li><strong>Attack Description</strong>: Comprehensive explanation of the attack mechanics and purpose</li>
 *   <li><strong>Detection Rationale</strong>: Detailed reasoning for why the specific failure type is expected</li>
 * </ul>
 *
 * <h3>2. Attack Databases</h3>
 * <p>Databases implement the {@link de.cuioss.http.security.database.AttackDatabase} interface and provide:</p>
 * <ul>
 *   <li><strong>Curated Attack Collections</strong>: Focused sets of related attack patterns</li>
 *   <li><strong>Public Constants</strong>: Individual test cases accessible for targeted testing</li>
 *   <li><strong>Complete Documentation</strong>: Each attack includes CVE details, vulnerability context</li>
 *   <li><strong>Educational Value</strong>: Comprehensive security knowledge embedded in test cases</li>
 * </ul>
 *
 * <h3>3. Database Categories</h3>
 *
 * <h4>CVE-Based Databases</h4>
 * <ul>
 *   <li><strong>{@link de.cuioss.http.security.database.ApacheCVEAttackDatabase}</strong>: Apache HTTP Server and Tomcat CVE exploits</li>
 *   <li><strong>{@link de.cuioss.http.security.database.IISCVEAttackDatabase}</strong>: Microsoft IIS and Windows-specific vulnerabilities</li>
 *   <li><strong>NginxCVEAttackDatabase</strong>: Nginx server CVE attack patterns (planned)</li>
 * </ul>
 *
 * <h4>Standards-Based Databases</h4>
 * <ul>
 *   <li><strong>{@link de.cuioss.http.security.database.OWASPTop10AttackDatabase}</strong>: OWASP Top 10 2021 attack vectors</li>
 *   <li><strong>HomographAttackDatabase</strong>: Unicode homograph attack patterns (planned)</li>
 *   <li><strong>IPv6AttackDatabase</strong>: IPv6-specific security attack patterns (planned)</li>
 * </ul>
 *
 * <h4>Technique-Based Databases</h4>
 * <ul>
 *   <li><strong>ProtocolHandlerAttackDatabase</strong>: Protocol manipulation attacks (planned)</li>
 *   <li><strong>XssAttackDatabase</strong>: Cross-site scripting attack patterns (planned)</li>
 *   <li><strong>IDNAttackDatabase</strong>: Internationalized Domain Name attacks (planned)</li>
 * </ul>
 *
 * <h2>Architecture Benefits</h2>
 *
 * <h3>1. Separation of Concerns</h3>
 * <ul>
 *   <li><strong>Databases vs Generators</strong>: Fixed attack patterns separated from dynamic generation</li>
 *   <li><strong>CVE Preservation</strong>: Exact vulnerability patterns preserved without algorithmic modification</li>
 *   <li><strong>Clear Purpose</strong>: Each class has a single, well-defined responsibility</li>
 * </ul>
 *
 * <h3>2. Enhanced Testing Capabilities</h3>
 * <ul>
 *   <li><strong>Specific Failure Testing</strong>: Each attack specifies expected {@code UrlSecurityFailureType}</li>
 *   <li><strong>Individual Test Access</strong>: Public constants enable targeted vulnerability testing</li>
 *   <li><strong>Comprehensive Coverage</strong>: Multiple databases cover different attack categories</li>
 *   <li><strong>Precise Validation</strong>: Expected vs actual failure type comparison for accuracy</li>
 * </ul>
 *
 * <h3>3. Educational and Documentation Value</h3>
 * <ul>
 *   <li><strong>Security Knowledge Base</strong>: Each attack includes detailed security education</li>
 *   <li><strong>CVE Research Integration</strong>: Official vulnerability details embedded in test cases</li>
 *   <li><strong>Attack Mechanics</strong>: Comprehensive explanations of how attacks work</li>
 *   <li><strong>Detection Rationale</strong>: Clear reasoning for security detection expectations</li>
 * </ul>
 *
 * <h2>Usage Patterns</h2>
 *
 * <h3>1. Parameterized Testing (Modern 2024-2025 Pattern)</h3>
 * <pre>
 * {@literal @}ParameterizedTest
 * {@literal @}ArgumentsSource(ApacheCVEAttackDatabase.ArgumentsProvider.class)
 * void shouldRejectAttacksWithCorrectFailureTypes(AttackTestCase testCase) {
 *     var exception = assertThrows(UrlSecurityException.class,
 *             () -> pipeline.validate(testCase.attackString()));
 *
 *     assertEquals(testCase.expectedFailureType(), exception.getFailureType(),
 *             String.format("Expected %s for attack: %s\nRationale: %s",
 *                     testCase.expectedFailureType(), testCase.attackString(),
 *                     testCase.detectionRationale()));
 * }
 * // NO MethodSource static method needed - ArgumentsProvider handles everything!
 * </pre>
 *
 * <h3>2. Specific Vulnerability Testing</h3>
 * <pre>
 * {@literal @}Test
 * void shouldDetectCVE202141773PathTraversal() {
 *     AttackTestCase testCase = ApacheCVEAttackDatabase.CVE_2021_41773_PATH_TRAVERSAL_PASSWD;
 *
 *     var exception = assertThrows(UrlSecurityException.class,
 *             () -> pipeline.validate(testCase.attackString()));
 *
 *     assertEquals(testCase.expectedFailureType(), exception.getFailureType());
 * }
 * </pre>
 *
 * <h3>3. Multiple Database Integration</h3>
 * <pre>
 * static Stream&lt;AttackTestCase&gt; getAllSecurityTestCases() {
 *     return Stream.of(
 *         new ApacheCVEAttackDatabase(),
 *         new IISCVEAttackDatabase(),
 *         new OWASPTop10AttackDatabase()
 *     ).flatMap(db -> StreamSupport.stream(db.getAttackTestCases().spliterator(), false));
 * }
 * </pre>
 *
 * <h2>Design Principles</h2>
 *
 * <h3>1. Immutability and Thread Safety</h3>
 * <ul>
 *   <li><strong>Record-Based Design</strong>: {@code AttackTestCase} is immutable by design</li>
 *   <li><strong>Unmodifiable Collections</strong>: Database implementations return immutable collections</li>
 *   <li><strong>Concurrent Testing</strong>: Safe for parallel test execution</li>
 * </ul>
 *
 * <h3>2. Comprehensive Documentation</h3>
 * <ul>
 *   <li><strong>Self-Documenting Tests</strong>: Each test case explains itself completely</li>
 *   <li><strong>Failure Message Quality</strong>: Detailed error messages with attack context</li>
 *   <li><strong>Educational Integration</strong>: Security learning embedded in testing framework</li>
 * </ul>
 *
 * <h3>3. Maintainability and Extension</h3>
 * <ul>
 *   <li><strong>Clear Patterns</strong>: Consistent structure across all database implementations</li>
 *   <li><strong>Easy Extension</strong>: New attacks added as public constants with documentation</li>
 *   <li><strong>Version Control Friendly</strong>: Individual test cases easy to track and modify</li>
 * </ul>
 *
 * <h2>Migration from Generators</h2>
 *
 * <p>This database approach replaces the previous generator-based testing for fixed attack patterns.
 * The migration provides several advantages:</p>
 *
 * <h3>Before (Generator-Based)</h3>
 * <pre>
 * private final TypedGenerator&lt;String&gt; patterns = Generators.fixedValues(
 *     "/cgi-bin/.%2e/%2e%2e/etc/passwd",  // No context or expected outcome
 *     "/another/attack/pattern"            // Hard to understand purpose
 * );
 * </pre>
 *
 * <h3>After (Database-Based)</h3>
 * <pre>
 * public static final AttackTestCase CVE_2021_41773_PATH_TRAVERSAL = new AttackTestCase(
 *     "/cgi-bin/.%2e/%2e%2e/etc/passwd",
 *     UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
 *     "CVE-2021-41773: Apache HTTP Server path traversal vulnerability...",
 *     "PATH_TRAVERSAL_DETECTED is expected because..."
 * );
 * </pre>
 *
 * <h2>Quality Assurance</h2>
 *
 * <h3>1. Attack Pattern Validation</h3>
 * <ul>
 *   <li><strong>CVE Accuracy</strong>: All CVE-based attacks verified against official sources</li>
 *   <li><strong>Pattern Effectiveness</strong>: Attack strings tested for actual vulnerability triggers</li>
 *   <li><strong>Documentation Quality</strong>: Comprehensive review of attack descriptions and rationales</li>
 * </ul>
 *
 * <h3>2. Test Coverage Analysis</h3>
 * <ul>
 *   <li><strong>Failure Type Coverage</strong>: Databases cover multiple {@code UrlSecurityFailureType} categories</li>
 *   <li><strong>Attack Vector Diversity</strong>: Different encoding techniques, protocols, and attack methods</li>
 *   <li><strong>Real-World Relevance</strong>: Patterns based on actual security incidents and research</li>
 * </ul>
 *
 * <h2>Future Enhancements</h2>
 *
 * <ul>
 *   <li><strong>Database Composition</strong>: Tools for combining multiple databases intelligently</li>
 *   <li><strong>Attack Evolution Tracking</strong>: Version management for evolving attack patterns</li>
 *   <li><strong>Performance Optimization</strong>: Lazy loading and caching for large database collections</li>
 *   <li><strong>Integration Testing</strong>: Cross-database compatibility and coverage analysis</li>
 * </ul>
 *
 * @author CUI OpenSource Software Development Team
 * @since 2.5
 * @see de.cuioss.http.security.database.AttackDatabase
 * @see de.cuioss.http.security.database.AttackTestCase
 * @see de.cuioss.http.security.core.UrlSecurityFailureType
 */
package de.cuioss.http.security.database;