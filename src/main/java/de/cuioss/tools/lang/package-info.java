/**
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
 * Provides core language utilities enhancing Java's basic functionality.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers fundamental utilities that enhance Java's core functionality,
 * focusing on arrays, objects, and locale handling.
 * It provides type-safe operations with proper null handling.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Object Utilities</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.lang.MoreObjects} - Enhanced object operations</li>
 *       <li>Null-safe object handling</li>
 *       <li>Object comparison and equality</li>
 *     </ul>
 *   </li>
 *   <li><b>Array Operations</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.lang.MoreArrays} - Array manipulation utilities</li>
 *       <li>Array comparison and validation</li>
 *       <li>Type-safe array operations</li>
 *     </ul>
 *   </li>
 *   <li><b>Locale Support</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.lang.LocaleUtils} - Locale handling utilities</li>
 *       <li>Locale parsing and validation</li>
 *       <li>Integration with Jakarta standards</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Object utilities
 * Object result = MoreObjects.firstNonNull(null, "default");
 * // Result: "default"
 *
 * boolean allNull = MoreObjects.allNull(null, null);
 * // Result: true
 *
 * // Array operations
 * String[] array = {"a", "b", "c"};
 * boolean isEmpty = MoreArrays.isEmpty(array);
 * // Result: false
 *
 * // Locale handling
 * Locale locale = LocaleUtils.toLocale("en_US");
 * boolean isValid = LocaleUtils.isISO639LanguageCode("en");
 * // Result: true
 *
 * // Type-safe operations
 * String str = MoreObjects.requireType(obj, String.class);
 * // Throws IllegalArgumentException if obj is not a String
 * </pre>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.lang.MoreObjects
 * @see de.cuioss.tools.lang.MoreArrays
 * @see de.cuioss.tools.lang.LocaleUtils
 */
package de.cuioss.tools.lang;
