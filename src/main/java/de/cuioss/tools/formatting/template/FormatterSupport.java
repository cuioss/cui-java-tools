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
package de.cuioss.tools.formatting.template;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Provides runtime-information about a bean without resorting to reflection.
 *
 * @author Eugen Fischer
 */
public interface FormatterSupport {

    /**
     * Allow easier access to available properties. Order of available properties
     * and their values has no effect.
     *
     * @return Map<String, Serializable> of property name -> property Value for
     *         <b>non</b> {@code null} properties
     */
    Map<String, Serializable> getAvailablePropertyValues();

    /**
     * @return list of all supported properties
     */
    List<String> getSupportedPropertyNames();

}
