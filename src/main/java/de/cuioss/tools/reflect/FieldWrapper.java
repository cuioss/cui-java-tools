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
package de.cuioss.tools.reflect;

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.Getter;
import lombok.NonNull;

import java.lang.reflect.Field;
import java.util.Optional;

import static de.cuioss.tools.ToolsLogMessages.WARN;

/**
 * Wraps a field and provides type-safe access to its value.
 * <p>
 * This class provides:
 * </p>
 * <ul>
 *   <li>Type-safe field access</li>
 *   <li>Proper exception handling</li>
 *   <li>Null-safe operations</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@SuppressWarnings("java:S3011")
// Sonar: "Reflection should not be used to increase accessibility of classes, methods, or fields"
// This is intentional and by design. FieldWrapper is specifically designed to provide controlled
// reflection access for framework-level operations (e.g., testing, serialization). The accessibility
// changes are properly encapsulated within this utility class and not exposed to end users.
public class FieldWrapper {

    private static final CuiLogger LOGGER = new CuiLogger(FieldWrapper.class);

    @Getter
    private final Field field;

    private final Class<?> declaringClass;

    /**
     * Creates a new field wrapper.
     *
     * @param field must not be null
     */
    public FieldWrapper(@NonNull Field field) {
        this.field = field;
        declaringClass = field.getDeclaringClass();
    }

    /**
     * Reads the field value from the given source object.
     * It implicitly sets the field accessible if needed.
     *
     * @param source the object to read from
     * @return an Optional containing the field value if successful, empty Optional otherwise
     */
    public Optional<Object> readValue(Object source) {
        if (null == source) {
            LOGGER.trace("No Object given, returning Optional#empty()");
            return Optional.empty();
        }
        if (!declaringClass.isAssignableFrom(source.getClass())) {
            LOGGER.trace("Given Object is improper type, returning Optional#empty()");
            return Optional.empty();
        }
        var initialAccessible = field.canAccess(source);
        LOGGER.trace("Reading from field '%s' with accessibleFlag='%s' ", field, initialAccessible);
        synchronized (field) {
            if (!initialAccessible) {
                LOGGER.trace("Explicitly setting accessible flag");
                field.setAccessible(true);
            }
            try {
                return Optional.ofNullable(field.get(source));
            } catch (IllegalArgumentException | IllegalAccessException e) {
                // cui-rewrite:disable CuiLogRecordPatternRecipe - Recipe bug: Cannot detect LogRecord through nested class
                LOGGER.warn(e, WARN.FIELD_READ_FAILED, field, initialAccessible, source);
                return Optional.empty();
            } finally {
                if (!initialAccessible) {
                    LOGGER.trace("Resetting accessible flag");
                    field.setAccessible(false);
                }
            }
        }
    }

    /**
     * Reads the value from the field in the given object. It implicitly sets and
     * resets the field accessibility.
     *
     * @param fieldName to be read
     * @param object    to be read from
     * @return the field value. {@link Optional#empty()} if the field cannot be read.
     */
    public static Optional<Object> readValue(final String fieldName, final Object object) {
        final var fieldProvider = from(object.getClass(), fieldName);
        LOGGER.trace("FieldWrapper: %s", fieldProvider);
        if (fieldProvider.isPresent()) {
            var fieldWrapper = fieldProvider.get();
            return fieldWrapper.readValue(object);
        }
        return Optional.empty();
    }

    /**
     * Writes the given value to the field of the target object.
     * It implicitly sets the field accessible if needed.
     *
     * @param target the object to write to
     * @param value  the value to write
     * @throws IllegalStateException if the field cannot be accessed
     * @throws NullPointerException if target is null
     */
    public void writeValue(@NonNull Object target, Object value) {
        var initialAccessible = field.canAccess(target);
        LOGGER.trace("Writing to field '%s' with accessibleFlag='%s' ", field, initialAccessible);
        synchronized (field) {
            if (!initialAccessible) {
                LOGGER.trace("Explicitly setting accessible flag");
                field.setAccessible(true);
            }
            try {
                field.set(target, value);
            } catch (IllegalAccessException e) {
                var message = MoreStrings.lenientFormat(
                        "Writing to field '{}' with accessible='{}' and parameter ='{}' could not complete", field,
                        initialAccessible, target);
                throw new IllegalStateException(message, e);
            } finally {
                if (!initialAccessible) {
                    LOGGER.trace("Resetting accessible flag");
                    field.setAccessible(false);
                }
            }
        }
    }

    /**
     * Factory Method for creating an {@link FieldWrapper} instance
     *
     * @param type      must not be null
     * @param fieldName must not be null
     * @return a {@link FieldWrapper} if the {@link Field} can be determined,
     * {@link Optional#empty()} otherwise
     */
    public static Optional<FieldWrapper> from(final Class<?> type, final String fieldName) {
        var loaded = MoreReflection.accessField(type, fieldName);
        return loaded.map(FieldWrapper::new);
    }
}
