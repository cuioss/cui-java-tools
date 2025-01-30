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

import static de.cuioss.tools.base.Preconditions.checkState;
import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static de.cuioss.tools.string.MoreStrings.requireNotEmpty;
import static java.util.Objects.requireNonNull;

import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.net.URL;
import java.util.Optional;

/**
 * Variant of {@link FileLoader} that loads files from the classpath.
 *
 * @author Oliver Wolff
 */
@EqualsAndHashCode(of = {"normalizedPathName"})
@ToString
public class ClassPathLoader implements FileLoader {

    @Serial
    private static final long serialVersionUID = 9140071059594577808L;

    private static final CuiLogger log = new CuiLogger(ClassPathLoader.class);

    private final String normalizedPathName;

    private final String givenPathName;

    @Getter
    private final StructuredFilename fileName;

    private URL url;

    /**
     * @param pathName must not be null nor empty, may start with the prefix
     *                 {@link FileTypePrefix#CLASSPATH} but not with
     *                 {@link FileTypePrefix#FILE} and contain at least one
     *                 character despite the prefix. On all other cases a
     *                 {@link IllegalArgumentException} will be thrown.
     */
    public ClassPathLoader(final String pathName) {
        requireNonNull(pathName);
        givenPathName = pathName;
        normalizedPathName = checkClasspathName(pathName);
        fileName = new StructuredFilename(FilenameUtils.getName(normalizedPathName));
    }

    /**
     * Checks and modifies a given pathName
     *
     * @param pathName must not be null nor empty, may start with the prefix
     *                 {@link FileTypePrefix#CLASSPATH} but not with
     *                 {@link FileTypePrefix#FILE} and contain at least one
     *                 character despite the prefix. On all other cases a
     *                 {@link IllegalArgumentException} will be thrown.
     * @return the normalized pathname without prefix but with a leading '/'
     */
    static String checkClasspathName(final String pathName) {
        requireNotEmpty(pathName);
        if (FileTypePrefix.FILE.is(pathName)) {
            throw new IllegalArgumentException(
                    "Invalid path name, must start not start with " + FileTypePrefix.FILE + " but was: " + pathName);
        }
        var newPathName = pathName;
        if (FileTypePrefix.CLASSPATH.is(pathName)) {
            newPathName = FileTypePrefix.CLASSPATH.removePrefix(pathName);
        }

        if (isEmpty(newPathName)) {
            throw new IllegalArgumentException("Filename " + pathName + " is invalid");
        }
        if (newPathName.indexOf('/') != 0) {
            newPathName = '/' + newPathName;
        }
        return newPathName;
    }

    @Override
    public boolean isReadable() {
        return null != getURL();
    }

    @Override
    public InputStream inputStream() {
        checkState(isReadable(), "Resource '%s' is not readable", givenPathName);
        try {
            return getURL().openStream();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to load classpath file for " + givenPathName, e);
        }
    }

    @Override
    public boolean isFilesystemLoader() {
        return false;
    }

    @Override
    public URL getURL() {
        if (null == url) {
            url = resolveUrl(normalizedPathName);
        }
        return url;
    }

    private static URL resolveUrl(String path) {
        log.debug("Resolving URL for '{}'", path);
        var url = ClassPathLoader.class.getResource(path);
        if (null != url) {
            log.debug("Resolved '{}' from ClassPathLoader.class", path);
            return url;
        }
        var loader = Optional.ofNullable(Thread.currentThread().getContextClassLoader());
        if (loader.isPresent()) {
            url = loader.get().getResource(path);
            if (null != url) {
                log.debug("Resolved '{}' from ContextClassLoader", path);
                return url;
            }
        }
        log.info("Unable to resolve '{}' from classpath", path);
        return null;
    }

}
