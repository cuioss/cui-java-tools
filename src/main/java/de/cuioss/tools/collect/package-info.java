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
 * Provides utilities for handling collections, maps, and arrays.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers utilities for working with Java collections, including
 * builders, difference calculation, and partial collection views. It focuses on
 * type safety and integration with CUI's logging standards.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Collection Builders</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.collect.CollectionBuilder} - Collection creation</li>
 *       <li>{@link de.cuioss.tools.collect.MapBuilder} - Map creation</li>
 *       <li>Type-safe collection initialization</li>
 *     </ul>
 *   </li>
 *   <li><b>Collection Operations</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.collect.MoreCollections} - Collection utilities</li>
 *       <li>{@link de.cuioss.tools.collect.PartialCollection} - Partial views</li>
 *       <li>Collection difference calculation</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Using MapBuilder
 * Map&lt;String, Integer&gt; map = MapBuilder.from("one", 1)
 *     .put("two", 2)
 *     .put("three", 3)
 *     .toImmutableMap();
 *
 * // Calculating map differences
 * Map&lt;String, Integer&gt; left = MapBuilder.from("a", 1).put("b", 2).toImmutableMap();
 * Map&lt;String, Integer&gt; right = MapBuilder.from("b", 2).put("c", 3).toImmutableMap();
 * MapDifference difference = MoreCollections.difference(left, right);
 *
 * // Using partial collections
 * List&lt;String&gt; originalList = Arrays.asList("a", "b", "c", "d", "e");
 * List&lt;String&gt; partialView = new PartialArrayList&lt;&gt;(originalList, 0, 3);
 * // partialView contains ["a", "b", "c"]
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Use builders for type-safe collection creation</li>
 *   <li>Consider immutable collections for thread safety</li>
 *   <li>Use partial views for large collections</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.collect.CollectionBuilder
 * @see de.cuioss.tools.collect.MapBuilder
 * @see de.cuioss.tools.collect.MoreCollections
 */
package de.cuioss.tools.collect;
