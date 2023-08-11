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
package de.cuioss.tools.support;

/**
 * A generator creates instances of type T. The method {@link #getType()}
 * provides a default implementation using {@link #next()} and reading the
 * concrete {@link Class} of the returned element.
 *
 * @author Oliver Wolff
 * @param <T> identifying the type of objects to be generated
 */
public interface TypedGenerator<T> {

    /**
     * @return class information; which type this generator is responsible for.
     */
    @SuppressWarnings("unchecked") // the implicit providing of the type is the actual idea
    default Class<T> getType() {
        return (Class<T>) next().getClass();
    }

    /**
     * Generates the next instance.
     *
     * @return a newly created instance
     */
    T next();
}
