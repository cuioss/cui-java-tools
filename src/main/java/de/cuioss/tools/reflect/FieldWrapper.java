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

import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.util.Optional;

import de.cuioss.tools.lang.SecuritySupport;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.Getter;
import lombok.NonNull;

/**
 * Wrapper around a {@link Field} that handles implicitly the accessible flag
 * for access.
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
     * Reads from the field determined by {@link #getField()}. It implicitly sets
     * and resets the {@link Field#isAccessible()} flag.
     *
     * @param object to be read from
     * @return an {@link Optional} on the given field value if applicable. May
     *         return {@link Optional#empty()} for cases where:
     *         <ul>
     *         <li>Field value is {@code null}</li>
     *         <li>Given Object is {@code null}</li>
     *         <li>Given Object is improper type</li>
     *         <li>an {@link IllegalAccessException} occurred while accessing</li>
     *         </ul>
     */
    public Optional<Object> readValue(Object object) {
        if (null == object) {
            log.trace("No Object given, returning Optional#empty()");
            return Optional.empty();
        }
        if (!declaringClass.isAssignableFrom(object.getClass())) {
            log.trace("Given Object is improper type, returning Optional#empty()");
            return Optional.empty();
        }
        var initialAccessible = field.canAccess(object);
        log.trace("Reading from field '{}' with accessibleFlag='{}' ", field, initialAccessible);
        synchronized (field) {
            if (!initialAccessible) {
                log.trace("Explicitly setting accessible flag");
                SecuritySupport.setAccessible(field, true);
            }
            try {
                return Optional.ofNullable(field.get(object));
            } catch (IllegalArgumentException | IllegalAccessException e) {
                log.warn(e, "Reading from field '{}' with accessible='{}' and parameter ='{}' could not complete",
                        field, initialAccessible, object);
                return Optional.empty();
            } finally {
                if (!initialAccessible) {
                    log.trace("Resetting accessible flag");
                    SecuritySupport.setAccessible(field, false);
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
     * Writes to the field determined by {@link #getField()}. It implicitly sets and
     * resets the {@link Field#isAccessible()} flag.
     *
     * @param object to be written to, must not be null
     * @param value  to be written, may be null
     *
     * @throws NullPointerException     in case object is {@code null}
     * @throws IllegalArgumentException in case the value is not applicable to the
     *                                  field
     * @throws IllegalStateException    wrapping an {@link IllegalAccessException}
     */
    public void writeValue(@NonNull Object object, Object value) {
        var initialAccessible = field.canAccess(object);
        log.trace("Writing to field '{}' with accessibleFlag='{}' ", field, initialAccessible);
        synchronized (field) {
            if (!initialAccessible) {
                log.trace("Explicitly setting accessible flag");
                SecuritySupport.setAccessible(field, true);
            }
            try {
                field.set(object, value);
            } catch (IllegalAccessException e) {
                var message = MoreStrings.lenientFormat(
                        "Writing to field '{}' with accessible='{}' and parameter ='{}' could not complete", field,
                        initialAccessible, object);
                throw new IllegalStateException(message, e);
            } finally {
                if (!initialAccessible) {
                    log.trace("Resetting accessible flag");
                    SecuritySupport.setAccessible(field, false);
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
