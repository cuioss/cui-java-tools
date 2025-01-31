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
package de.cuioss.tools.io;

import lombok.Getter;

import static java.util.Objects.requireNonNull;

/**
 * Utility class to define file type prefixes.
 *
 * @author Sven Haag
 */
public enum FileTypePrefix {

    /** "file:" */
    FILE("file:"),

    /** "classpath:" */
    CLASSPATH("classpath:"),

    /** "external:" */
    EXTERNAL("external:"),

    /** "url:" */
    URL("url:");

    @Getter
    private final String prefix;

    FileTypePrefix(final String prefix) {
        this.prefix = prefix;
    }

    /**
     * @param path to be checked
     *
     * @return true if the given path is prefixed with this enum
     */
    public boolean is(final String path) {
        return null != path && path.startsWith(getPrefix());
    }

    /**
     * @param path from which the prefix should be removed
     *
     * @return path without the prefix, if any
     */
    public String removePrefix(final String path) {
        requireNonNull(path);
        if (is(path)) {
            return path.substring(getPrefix().length());
        }
        return path;
    }

    @Override
    public String toString() {
        return prefix;
    }
}
