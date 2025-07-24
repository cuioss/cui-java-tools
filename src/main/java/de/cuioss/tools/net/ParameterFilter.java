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
package de.cuioss.tools.net;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;

/**
 * Defines a filter identifying which parameters are not to be included within
 * url parameter handling. Therefore, it filters parameter prefixed with
 * "javax.faces", depending on <code>excludeFacesParameter</code> and
 * additionally a given list of parameter names.
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
@EqualsAndHashCode
@ToString
public class ParameterFilter implements Serializable {

    @Serial
    private static final long serialVersionUID = -4780294784318006024L;

    private static final String JAVAX_FACES = "javax.faces";

    /**
     * The list of string to be excluded from the parameter-list. Because the test
     * utilizes toLowerCase() the members of the list must all be lowercase.
     * Otherwise, they are not considered.
     */
    @NonNull
    @Getter
    private final List<String> excludes;

    /** Flag indicating whether to exclude technical jsf parameters. */
    private final boolean excludeFacesParameter;

    /**
     * @param value as key of view parameter. Must not be null
     * @return true if value belongs to excluded values
     */
    public boolean isExcluded(@NonNull final String value) {
        var excluded = false;
        if (excludeFacesParameter) {
            excluded = value.startsWith(JAVAX_FACES);
        }
        if (!excluded) {
            excluded = excludes.contains(value.toLowerCase());
        }
        return excluded;
    }

}
