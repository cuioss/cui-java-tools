/**
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
package de.cuioss.tools.formatting.template;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Base interface for all formatters.
 * Each implementation must provide a method for retrieving all properties that can be used for formatting.
 *
 * @author Oliver Wolff
 */
public interface FormatterSupport {

    /**
     * @return A map containing property names and their corresponding values.
     * The values must be {@link Serializable}.
     */
    Map<String, Serializable> getAvailablePropertyValues();

    /**
     * @return list of all supported properties
     */
    List<String> getSupportedPropertyNames();

}
