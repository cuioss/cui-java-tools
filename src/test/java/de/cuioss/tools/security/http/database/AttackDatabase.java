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
package de.cuioss.tools.security.http.database;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Interface for attack databases that provide collections of security test cases.
 *
 * <p>This interface standardizes how attack databases expose their test cases,
 * enabling consistent access to attack patterns across different attack types
 * and sources. Attack databases contain curated collections of known attack
 * patterns with their expected detection outcomes and comprehensive documentation.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Standardized Access</strong> - Uniform interface for all attack databases</li>
 *   <li><strong>Iterable Design</strong> - Easy integration with parameterized tests</li>
 *   <li><strong>Comprehensive Coverage</strong> - Each database covers specific attack categories</li>
 *   <li><strong>Documentation First</strong> - Every attack includes educational context</li>
 * </ul>
 *
 * <h3>Implementation Guidelines</h3>
 * <ul>
 *   <li><strong>Static Constants</strong> - Expose individual test cases as public static final constants</li>
 *   <li><strong>Immutable Collections</strong> - Return unmodifiable collections of test cases</li>
 *   <li><strong>Thread Safety</strong> - Implementations must be thread-safe for concurrent testing</li>
 *   <li><strong>Complete Documentation</strong> - Every AttackTestCase must have thorough descriptions</li>
 * </ul>
 *
 * <h3>Usage Example</h3>
 * <pre>
 * public class SqlInjectionAttackDatabase implements AttackDatabase {
 *     public static final AttackTestCase UNION_SELECT = new AttackTestCase(
 *         "' UNION SELECT 1,2,3--",
 *         UrlSecurityFailureType.SQL_INJECTION_DETECTED,
 *         "Classic UNION-based SQL injection attack",
 *         "Contains SQL UNION keyword and comment syntax"
 *     );
 *
 *     &#64;Override
 *     public Iterable&lt;AttackTestCase&gt; getAttackTestCases() {
 *         return List.of(UNION_SELECT);
 *     }
 * }
 *
 * // Usage in tests
 * &#64;ParameterizedTest
 * &#64;MethodSource("getAttackTestCases")
 * void testAttackDetection(AttackTestCase testCase) {
 *     // Test implementation
 * }
 *
 * static Stream&lt;AttackTestCase&gt; getAttackTestCases() {
 *     return StreamSupport.stream(
 *         new SqlInjectionAttackDatabase().getAttackTestCases().spliterator(),
 *         false
 *     );
 * }
 * </pre>
 *
 * <h3>Database Categories</h3>
 * <p>Expected implementations include:</p>
 * <ul>
 *   <li><strong>CVE Databases</strong> - Apache, Nginx, IIS CVE attack patterns</li>
 *   <li><strong>Injection Databases</strong> - SQL, XSS, Command injection patterns</li>
 *   <li><strong>Protocol Databases</strong> - HTTP/2, IPv6, encoding attack patterns</li>
 *   <li><strong>Standard Databases</strong> - OWASP Top 10, common attack signatures</li>
 * </ul>
 *
 * @since 2.5
 */
public interface AttackDatabase {

    /**
     * Returns an iterable collection of all attack test cases in this database.
     *
     * <p>The returned collection should be immutable and thread-safe. Each AttackTestCase
     * must contain a complete attack string, expected failure type, and comprehensive
     * documentation explaining both the attack mechanics and detection rationale.</p>
     *
     * <p>Implementations should organize test cases logically and ensure comprehensive
     * coverage of the attack category they represent. Test cases should progress from
     * simple to complex patterns to aid in debugging and understanding.</p>
     *
     * @return An iterable collection of AttackTestCase instances, never null
     * @throws UnsupportedOperationException if the returned collection is modified
     */
    Iterable<AttackTestCase> getAttackTestCases();

    /**
     * Returns a stream of all attack test cases in this database for convenient parameterized testing.
     *
     * <p>This method provides a convenient way to use attack databases with JUnit 5 parameterized tests
     * without requiring boilerplate StreamSupport code. The stream is created from the iterable
     * returned by {@link #getAttackTestCases()}.</p>
     *
     * @return A stream of AttackTestCase instances, never null
     * @since 2.5
     */
    default Stream<AttackTestCase> streamTestCases() {
        return StreamSupport.stream(
                getAttackTestCases().spliterator(),
                false
        );
    }

    /**
     * Abstract base class for creating ArgumentsProvider implementations that eliminate @MethodSource boilerplate.
     *
     * <p><strong>Modern JUnit 5 Pattern (2024-2025):</strong> This approach uses static nested classes
     * to provide test arguments directly via @ArgumentsSource, eliminating the need for @MethodSource
     * and static method declarations.</p>
     *
     * <h3>Implementation Pattern</h3>
     * <p>Database classes should include a static nested ArgumentsProvider class:</p>
     * <pre>
     * public class ApacheCVEAttackDatabase implements AttackDatabase {
     *     // Database implementation...
     *
     *     public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider&lt;ApacheCVEAttackDatabase&gt; {
     *         // No implementation needed - uses reflection to create database instance
     *     }
     * }
     * </pre>
     *
     * <h3>Clean Test Usage</h3>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(ApacheCVEAttackDatabase.ArgumentsProvider.class)
     * void shouldRejectApacheCVEAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO MethodSource boilerplate needed!
     * }
     * </pre>
     *
     * @param <T> The specific attack database type
     * @since 2.5
     */
    abstract static class ArgumentsProvider<T extends AttackDatabase>
            implements org.junit.jupiter.params.provider.ArgumentsProvider {

        @Override
        @SuppressWarnings("unchecked")
        public Stream<Arguments> provideArguments(
                ExtensionContext context) throws Exception {

            // Get the concrete ArgumentsProvider class
            Class<?> providerClass = this.getClass();

            // Extract the database class from generic parameter using reflection
            java.lang.reflect.ParameterizedType genericSuperclass =
                    (java.lang.reflect.ParameterizedType) providerClass.getGenericSuperclass();
            Class<T> databaseClass = (Class<T>) genericSuperclass.getActualTypeArguments()[0];

            // Create database instance and stream test cases as Arguments
            T database = databaseClass.getDeclaredConstructor().newInstance();
            return database.streamTestCases()
                    .map(Arguments::of);
        }
    }


    /**
     * Returns the name of this attack database for identification and logging purposes.
     *
     * <p>The database name should be descriptive and identify the attack category
     * or source (e.g., "Apache CVE Database", "SQL Injection Database").</p>
     *
     * @return A human-readable name for this attack database, never null or blank
     */
    default String getDatabaseName() {
        return this.getClass().getSimpleName();
    }

    /**
     * Returns a brief description of what types of attacks this database contains.
     *
     * <p>This description should help users understand the scope and coverage
     * of the attack patterns in this database.</p>
     *
     * @return A description of the attack patterns in this database, never null
     */
    default String getDescription() {
        return "Attack database containing security test cases for HTTP validation";
    }
}