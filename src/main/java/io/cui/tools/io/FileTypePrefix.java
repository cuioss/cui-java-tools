package io.cui.tools.io;

import static java.util.Objects.requireNonNull;

import lombok.Getter;

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
     * @return path without {@link #getPrefix()}
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
