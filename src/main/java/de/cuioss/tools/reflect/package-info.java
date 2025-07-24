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
 * Provides enhanced reflection utilities with type-safe operations.
 *
 * <h2>Overview</h2>
 * This package offers utilities for reflection operations with a focus on type safety
 * and proper error handling.
 * It provides comprehensive field access capabilities while maintaining compatibility with Java Bean standards.
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Core Reflection</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.reflect.MoreReflection} - Enhanced reflection operations</li>
 *       <li>Type-safe field and method access with caching</li>
 *       <li>Efficient class loading and instantiation</li>
 *     </ul>
 *   </li>
 *   <li><b>Field Operations</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.reflect.FieldWrapper} - Type-safe field access</li>
 *       <li>Proper access control and visibility handling</li>
 *       <li>Memory-efficient field caching</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * Accessing fields:
 * <pre>{@code
 * // Access a field with proper caching
 * Optional<Field> field = MoreReflection.accessField(targetClass, "fieldName");
 * 
 * // Create a type-safe field wrapper
 * FieldWrapper wrapper = new FieldWrapper(field.get());
 * }</pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Use {@link de.cuioss.tools.reflect.FieldWrapper} for type-safe field access</li>
 *   <li>Leverage caching for better performance</li>
 *   <li>Handle security exceptions appropriately</li>
 *   <li>Consider using property utilities for Java Bean access</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.reflect.MoreReflection
 * @see de.cuioss.tools.reflect.FieldWrapper
 * @see de.cuioss.tools.property.PropertyUtil
 */
package de.cuioss.tools.reflect;
