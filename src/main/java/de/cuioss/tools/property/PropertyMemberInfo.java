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

import de.cuioss.tools.reflect.MoreReflection;

import java.io.Serializable;
import java.lang.reflect.Modifier;

/**
 * Members of this enum define the way the corresponding property is subject to
 * the contracts regarding the canonical {@link Object} methods like
 * {@link Object#equals(Object)}, {@link Object#hashCode()} and
 * {@link Object#toString()} and the {@link Serializable} contract
 *
 * @author Oliver Wolff
 */
public enum PropertyMemberInfo {

    /**
     * Defines a default property contract, saying it is not transient and defines
     * the Object-identity, {@link Object#equals(Object)}, {@link Object#hashCode()}
     * and {@link Object#toString()}
     */
    DEFAULT,

    /**
     * Defines a property that is not transient, and is not part of the
     * object-identity and should therefore be ignored in the methods
     * {@link Object#equals(Object)}, {@link Object#hashCode()}
     */
    NO_IDENTITY,

    /**
     * Defines a transient property that is not part of the object-identity and
     * should therefore be ignored in the methods {@link Object#equals(Object)} and
     * the serialization.
     */
    TRANSIENT,

    /** The actual state can not be defined. */
    UNDEFINED;

    /**
     * Resolves {@link PropertyMemberInfo} for a given property with
     * {@link MoreReflection}. This method can solely distinguish between the states
     * {@link #UNDEFINED}, {@link #DEFAULT} and {@link #TRANSIENT}.
     * {@link #NO_IDENTITY} must be defined from the caller if necessary;
     *
     * @param beanType     to be checked, must not be null
     * @param propertyName to be checked, must not be null
     * @return the corresponding {@link PropertyReadWrite} for a given property
     */
    public static PropertyMemberInfo resolveForBean(final Class<?> beanType, final String propertyName) {
        var fieldOption = MoreReflection.accessField(beanType, propertyName);
        if (fieldOption.isEmpty()) {
            return UNDEFINED;
        }
        if (Modifier.isTransient(fieldOption.get().getModifiers())) {
            return PropertyMemberInfo.TRANSIENT;
        }
        return PropertyMemberInfo.DEFAULT;
    }
}
