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
 * Provides utilities for handling Java properties and bean properties.
 *
 * <h2>Overview</h2>
 * This package offers utilities for working with properties, focusing on type-safe
 * property access and manipulation. It provides comprehensive property management 
 * capabilities while maintaining compatibility with Java Bean standards.
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Property Management</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.property.PropertyHolder} - Type-safe property container</li>
 *       <li>{@link de.cuioss.tools.property.PropertyUtil} - Reflection-based property access</li>
 *       <li>Support for Java Bean specification compliant properties</li>
 *     </ul>
 *   </li>
 *   <li><b>Property Metadata</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.property.PropertyMemberInfo} - Object identity and serialization</li>
 *       <li>{@link de.cuioss.tools.property.PropertyReadWrite} - Read/write access control</li>
 *       <li>Comprehensive property validation</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * Reading a property:
 * <pre>{@code
 * // Read a property value
 * Object value = PropertyUtil.readProperty(bean, "propertyName");
 * 
 * // Create a type-safe property holder
 * Optional<PropertyHolder> holder = PropertyHolder.from(beanClass, "propertyName");
 * }</pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Use {@link de.cuioss.tools.property.PropertyHolder} for type-safe property access</li>
 *   <li>Prefer standard getter/setter methods over reflection</li>
 *   <li>Handle property access exceptions appropriately</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.property.PropertyHolder
 * @see de.cuioss.tools.property.PropertyUtil
 * @see de.cuioss.tools.property.PropertyReadWrite
 */
package de.cuioss.tools.property;
