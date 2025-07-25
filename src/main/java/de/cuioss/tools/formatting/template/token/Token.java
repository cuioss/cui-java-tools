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
package de.cuioss.tools.formatting.template.token;

import de.cuioss.tools.formatting.template.FormatterSupport;

import java.io.Serializable;

/**
 * Any token should provide a method to substitute "placeholder" with his value
 *
 * @author Eugen Fischer
 */
public interface Token extends Serializable {

    /**
     * @param content must not be null
     * @return token specific template with substituted attribute value if attribute
     *         exists, <code>empty</code> String otherwise
     */
    String substituteAttribute(FormatterSupport content);

    /**
     * @return true if Token has no substitutions
     */
    boolean isStringToken();

}
