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
package de.cuioss.tools.io;

import de.cuioss.tools.string.Splitter;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.File;
import java.io.Serial;
import java.io.Serializable;
import java.nio.file.Path;

/**
 * Helper class for splitting / interacting with Filename and corresponding
 * suffixes.
 *
 * @author Oliver Wolff
 */
@EqualsAndHashCode
@ToString
public class StructuredFilename implements Serializable {

    @Serial
    private static final long serialVersionUID = 7473756881958645393L;

    @Getter
    private final String originalName;

    @Getter
    private final String namePart;

    @Getter
    private final String suffix;

    /**
     * Constructor.
     *
     * @param filename to be checked
     */
    @SuppressWarnings("squid:S1871") // owolff: Although duplicate code for case 0 and case 1 I find
    // it better readable
    public StructuredFilename(final String filename) {
        originalName = filename;
        final var list = Splitter.on('.').omitEmptyStrings().splitToList(filename);
        switch (list.size()) {
            case 0, 1:
                namePart = filename;
                suffix = null;
                break;
            case 2:
                namePart = list.get(0);
                suffix = list.get(1);
                break;
            default:
                suffix = list.get(list.size() - 1);
                namePart = String.join(".", list.subList(0, list.size() - 1));
                break;
        }
    }

    /**
     * Constructor
     *
     * @param path to be used as source, must not be null
     */
    public StructuredFilename(final Path path) {
        this(path.getName(path.getNameCount() - 1).toString());
    }

    /**
     * Constructor
     *
     * @param file to be used as source, must not be null
     */
    public StructuredFilename(final File file) {
        this(file.toPath());
    }

    /**
     * @param nameSuffix to be used for appending the name part. may be null
     * @return the created name string. if namePart = "namePart",
     *         nameSuffix=".nameSuffix" and suffix = "suffix" the resulting String
     *         will be "namePart.nameSuffix.suffix"
     */
    public String getAppendedName(final String nameSuffix) {
        final var builder = new StringBuilder(namePart);
        if (null != nameSuffix) {
            builder.append(nameSuffix);
        }
        if (null != suffix) {
            builder.append('.');
            builder.append(suffix);
        }
        return builder.toString();
    }
}
