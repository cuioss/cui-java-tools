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
package de.cuioss.tools.reflect;

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.Getter;
import lombok.NonNull;

import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.util.Optional;

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
 *
 */
@SuppressWarnings("java:S3011") // owolff: The warning is "Reflection should not be used to
// increase accessibility of classes, methods, or fields "
// What is actually the use-case of this type, therefore there
// is nothing we can do
public class FieldWrapper {

    private static final CuiLogger log = new CuiLogger(FieldWrapper.class);

    @Getter
    @NonNull
    private final Field field;

    private final Class<?> declaringClass;

    /**
     * @param field must not be null
     */
    public FieldWrapper(Field field) {
        this.field = field;
        declaringClass = ((Member) field).getDeclaringClass();
    }

    /**
     * Reads the field value from the given source object.
     * It implicitly sets the field accessible if needed.
     *
     * @param source the object to read from
     * @return the field value
     * @throws IllegalArgumentException if the source is null or the field cannot be accessed
     */
    public Optional<Object> readValue(Object source) {
        if (null == source) {
            log.trace("No Object given, returning Optional#empty()");
            return Optional.empty();
        }
        if (!declaringClass.isAssignableFrom(source.getClass())) {
            log.trace("Given Object is improper type, returning Optional#empty()");
            return Optional.empty();
        }
        var initialAccessible = field.canAccess(source);
        log.trace("Reading from field '{}' with accessibleFlag='{}' ", field, initialAccessible);
        synchronized (field) {
            if (!initialAccessible) {
                log.trace("Explicitly setting accessible flag");
                field.setAccessible(true);
            }
            try {
                return Optional.ofNullable(field.get(source));
            } catch (IllegalArgumentException | IllegalAccessException e) {
                log.warn(e, "Reading from field '{}' with accessible='{}' and parameter ='{}' could not complete",
                        field, initialAccessible, source);
                return Optional.empty();
            } finally {
                if (!initialAccessible) {
                    log.trace("Resetting accessible flag");
                    field.setAccessible(false);
                }
            }
        }
    }

    /**
     * Reads the value from the field in the given object. It implicitly sets and
     * resets the {@link Field#isAccessible()} flag.
     *
     * @param fieldName to be read
     * @param object    to be read from
     *
     * @return the field value. {@link Optional#empty()} if the field cannot be
     *         read.
     */
    public static final Optional<Object> readValue(final String fieldName, final Object object) {
        final var fieldProvider = from(object.getClass(), fieldName);
        log.trace("FieldWrapper: {}", fieldProvider);
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
     * @throws IllegalArgumentException if the target is null or the field cannot be accessed
     */
    public void writeValue(@NonNull Object target, Object value) {
        var initialAccessible = field.canAccess(target);
        log.trace("Writing to field '{}' with accessibleFlag='{}' ", field, initialAccessible);
        synchronized (field) {
            if (!initialAccessible) {
                log.trace("Explicitly setting accessible flag");
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
                    log.trace("Resetting accessible flag");
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
     *         {@link Optional#empty()} otherwise
     */
    public static final Optional<FieldWrapper> from(final Class<?> type, final String fieldName) {
        var loaded = MoreReflection.accessField(type, fieldName);
        if (loaded.isPresent()) {
            return Optional.of(new FieldWrapper(loaded.get()));
        }
        return Optional.empty();
    }
}
