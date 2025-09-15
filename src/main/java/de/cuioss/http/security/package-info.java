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
 * Comprehensive HTTP security validation framework for web applications.
 *
 * <p>This package provides a complete solution for validating HTTP components against
 * security threats including path traversal, injection attacks, malicious headers,
 * and other common web application vulnerabilities.</p>
 *
 * <h3>Core Components</h3>
 * <ul>
 *   <li><strong>Configuration System</strong> - {@link de.cuioss.tools.security.http.SecurityConfiguration}</li>
 *   <li><strong>Validation Interface</strong> - {@link de.cuioss.tools.security.http.HttpSecurityValidator}</li>
 *   <li><strong>Data Records</strong> - {@link de.cuioss.tools.security.http.URLParameter},
 *       {@link de.cuioss.tools.security.http.Cookie}, {@link de.cuioss.tools.security.http.HTTPBody}</li>
 *   <li><strong>Exception Handling</strong> - {@link de.cuioss.tools.security.http.UrlSecurityException}</li>
 *   <li><strong>Type Safety</strong> - {@link de.cuioss.tools.security.http.UrlSecurityFailureType},
 *       {@link de.cuioss.tools.security.http.ValidationType}</li>
 * </ul>
 *
 * <h3>Package Nullability</h3>
 * <p>This package follows strict nullability conventions using JSpecify annotations:</p>
 * <ul>
 *   <li>All parameters and return values are non-null by default</li>
 *   <li>Nullable parameters and return values are explicitly annotated with {@code @Nullable}</li>
 *   <li>Optional return values use {@code Optional<T>} to indicate potential absence of values</li>
 * </ul>
 *
 * @since 2.5
 * @see de.cuioss.tools.security.http.SecurityConfiguration
 * @see de.cuioss.tools.security.http.HttpSecurityValidator
 */
@NullMarked
package de.cuioss.http.security;

import org.jspecify.annotations.NullMarked;