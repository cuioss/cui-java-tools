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
 * Provides a template-based formatting system for displaying complex objects.
 *
 * <h2>Overview</h2>
 * <p>
 * This package is the entry point for the formatting subsystem. It combines
 * simple concatenation-style formatting with a template engine that resolves
 * attribute placeholders against bean properties.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li>{@link de.cuioss.tools.formatting.SimpleFormatter} - Joins property
 *       values with a separator, ignoring missing values</li>
 *   <li>{@link de.cuioss.tools.formatting.template} - Template-based
 *       formatting using placeholder expressions like
 *       {@code "[familyName], [givenName]"}</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * String result = SimpleFormatter.builder()
 *         .ignoreMissingValues()
 *         .separatesBy(", ")
 *         .format("John", null, "Doe");
 * // result: "John, Doe"
 * }</pre>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.formatting.template.TemplateFormatter
 */
package de.cuioss.tools.formatting;
