/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.property;

import java.io.Serializable;
import java.lang.reflect.Modifier;
import java.util.Optional;

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.reflect.MoreReflection;

/**
 * Members of this enum define how a property participates in object identity and
 * serialization contracts.
 * This affects the property's behavior in:
 * <ul>
 *   <li>{@link Object#equals(Object)} - Object equality comparison</li>
 *   <li>{@link Object#hashCode()} - Hash code generation</li>
 *   <li>{@link Object#toString()} - String representation</li>
 *   <li>{@link java.io.Serializable} - Serialization handling</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @since 2.0
 */
public enum PropertyMemberInfo {

    /**
     * Defines a default property contract. The property:
     * <ul>
     *   <li>Is not transient</li>
     *   <li>Participates in object identity</li>
     *   <li>Is included in equals, hashCode and toString</li>
     * </ul>
     */
    DEFAULT,

    /**
     * Defines a property that:
     * <ul>
     *   <li>Is not transient</li>
     *   <li>Does not participate in object identity</li>
     *   <li>Is excluded from equals and hashCode</li>
     * </ul>
     */
    NO_IDENTITY,

    /**
     * Defines a transient property that:
     * <ul>
     *   <li>Is marked as transient</li>
     *   <li>Does not participate in object identity</li>
     *   <li>Is excluded from equals, hashCode and serialization</li>
     * </ul>
     */
    TRANSIENT,

    /**
     * Indicates that the property's state cannot be determined.
     * This usually occurs when the property cannot be resolved
     * through standard reflection mechanisms.
     */
    UNDEFINED;

    private static final CuiLogger LOGGER = new CuiLogger(PropertyMemberInfo.class);

    /**
     * Resolves {@link PropertyMemberInfo} for a given property using reflection.
     * This method can distinguish between {@link #UNDEFINED}, {@link #DEFAULT}
     * and {@link #TRANSIENT} states.
     * must be defined by the caller if necessary.
     *
     * @param beanType     type to be checked, must not be null
     * @param propertyName name of property to be checked, must not be null
     * @return the corresponding {@link PropertyMemberInfo} for the given property
     * @since 2.0
     */
    public static PropertyMemberInfo resolveForBean(final Class<?> beanType, final String propertyName) {
        var fieldOption = MoreReflection.accessField(beanType, propertyName);
        if (fieldOption.isEmpty()) {
            LOGGER.debug("No property descriptor found for property %s on type %s", propertyName, beanType);
            return UNDEFINED;
        }
        if (Modifier.isTransient(fieldOption.get().getModifiers())) {
            return PropertyMemberInfo.TRANSIENT;
        }
        return PropertyMemberInfo.DEFAULT;
    }
}
