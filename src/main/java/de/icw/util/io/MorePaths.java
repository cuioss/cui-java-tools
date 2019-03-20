/**
 * Copyright 2018, InterComponentWare AG
 *
 * NO WARRANTIES OR ANY FURTHER CONDITIONS are implied as to the availability
 * of this source code.
 *
 * In case you receive a copy of this source code you are not permitted
 * to modify, use, or distribute this copy without agreement and an explicit
 * license issued by InterComponentWare AG.
 */
package de.icw.util.io;

import static java.util.Objects.requireNonNull;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import de.icw.util.logging.Logger;

/**
 * Provides {@link Path} related utilities
 *
 * @author i001428, Oliver Wolff
 *
 */
public final class MorePaths {

    private static final Logger LOG = new Logger(MorePaths.class);

    /**
     * Tries to determine the real-path by calling
     * {@link Path#toRealPath(java.nio.file.LinkOption...)} with no further parameter passed. In
     * case the real path can not be resolved it will log at warn-level and return
     * {@link Path#toAbsolutePath()}.
     *
     * @param path must not be null
     * @return the real-path if applicable, {@link Path#toAbsolutePath()} otherwise.
     */
    public static Path getRealPathSafely(Path path) {
        requireNonNull(path, "Path must not be null");
        try {
            return path.toRealPath();
        } catch (IOException e) {
            LOG.warn("Unable to resolve real path for '{}', due to '{}'. Returning absolutePath.", path, e.getMessage(),
                    e);
            return path.toAbsolutePath();
        }
    }

    /**
     * Tries to determine the real-path, see {@link #getRealPathSafely(Path)} for details and
     * {@link Paths#get(String, String...)} for details regarding the parameter
     *
     * @param first
     *            the path string or initial part of the path string
     * @param more
     *            additional strings to be joined to form the path string
     * @return the real-path if applicable, {@link Path#toAbsolutePath()} otherwise.
     */
    public static Path getRealPathSafely(String first, String... more) {
        return getRealPathSafely(Paths.get(first, more));
    }

    /**
     * Tries to determine the real-path, see {@link #getRealPathSafely(Path)} for details
     *
     * @param file the {@link File} to be looked up
     *
     * @return the real-path if applicable, {@link Path#toAbsolutePath()} otherwise.
     */
    public static Path getRealPathSafely(File file) {
        requireNonNull(file, "File must not be null");
        return getRealPathSafely(file.toPath());
    }

    private MorePaths() {
        // Utility class
    }
}
