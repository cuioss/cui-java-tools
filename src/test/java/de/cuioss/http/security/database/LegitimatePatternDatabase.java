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

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Interface for legitimate pattern databases that provide collections of valid URL patterns
 * for false positive prevention testing.
 *
 * <p>This interface standardizes how legitimate pattern databases expose their test cases,
 * enabling consistent testing of valid URL patterns that must not be rejected by security
 * validation. These databases help prevent false positives that could impact legitimate
 * business operations.</p>
 *
 * <h3>Purpose</h3>
 * <p>While {@link AttackDatabase} focuses on patterns that should be rejected,
 * LegitimatePatternDatabase focuses on patterns that must be accepted to ensure
 * the security validation doesn't interfere with normal application functionality.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>False Positive Prevention</strong> - Ensures valid patterns aren't rejected</li>
 *   <li><strong>Business Case Coverage</strong> - Covers real-world URL patterns</li>
 *   <li><strong>Edge Case Validation</strong> - Tests unusual but valid constructs</li>
 *   <li><strong>Documentation Focus</strong> - Clear rationale for acceptance</li>
 * </ul>
 *
 * @since 2.5
 */
public interface LegitimatePatternDatabase {

    /**
     * Returns an iterable collection of all legitimate test cases in this database.
     *
     * <p>The returned collection should be immutable and thread-safe. Each LegitimateTestCase
     * must contain a valid URL pattern and comprehensive documentation explaining why it
     * represents a legitimate use case that must be accepted.</p>
     *
     * @return An iterable collection of LegitimateTestCase instances, never null
     * @throws UnsupportedOperationException if the returned collection is modified
     */
    Iterable<LegitimateTestCase> getLegitimateTestCases();

    /**
     * Returns a stream of all legitimate test cases for convenient parameterized testing.
     *
     * @return A stream of LegitimateTestCase instances, never null
     */
    default Stream<LegitimateTestCase> streamTestCases() {
        return StreamSupport.stream(
                getLegitimateTestCases().spliterator(),
                false
        );
    }

    /**
     * Abstract base class for creating ArgumentsProvider implementations for legitimate patterns.
     *
     * @param <T> The specific legitimate pattern database type
     */
    abstract static class ArgumentsProvider<T extends LegitimatePatternDatabase>
            implements org.junit.jupiter.params.provider.ArgumentsProvider {

        @Override
        @SuppressWarnings("unchecked")
        public Stream<Arguments> provideArguments(ExtensionContext context) throws Exception {
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
     * Returns the name of this legitimate pattern database for identification and logging.
     *
     * @return A human-readable name for this database, never null or blank
     */
    default String getDatabaseName() {
        return this.getClass().getSimpleName();
    }

    /**
     * Returns a brief description of what types of legitimate patterns this database contains.
     *
     * @return A description of the legitimate patterns in this database, never null
     */
    default String getDescription() {
        return "Legitimate pattern database containing valid URL patterns for false positive prevention";
    }
}