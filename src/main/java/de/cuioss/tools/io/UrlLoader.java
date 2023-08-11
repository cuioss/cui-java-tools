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

import static de.cuioss.tools.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * This {@link FileLoader} takes a {@link URL} as its parameter which is useful
 * when e.g. iterating over an enumeration of URLs from
 * {@link ClassLoader#getResources(String)}. It converts the given URL to a
 * {@code String} and prefixes it with {@link FileTypePrefix#URL}.
 *
 * @author Sven Haag
 */
@EqualsAndHashCode(of = { "url" })
@ToString(of = { "url" })
public class UrlLoader implements FileLoader {

    private static final long serialVersionUID = -8758614099334823819L;

    private static final CuiLogger log = new CuiLogger(UrlLoader.class);

    private final URL url;
    private transient URLConnection connection;

    /**
     * @param url representing a valid URL
     * @throws IllegalArgumentException indicating that the given String represents
     *                                  a valid URL
     */
    public UrlLoader(final String url) {
        var sanitizedUrl = url;
        if (FileTypePrefix.URL.is(url)) {
            sanitizedUrl = FileTypePrefix.URL.removePrefix(url);
        }

        try {
            this.url = new URL(sanitizedUrl);
        } catch (final MalformedURLException e) {
            throw new IllegalArgumentException("Provided URL is invalid: " + url, e);
        }
    }

    /**
     * @param url hopefully a JAR URL
     */
    public UrlLoader(final URL url) {
        checkArgument(null != url, "url must not be null");
        this.url = url;
    }

    /**
     * @return true, if a connection to {@link #getURL()} can be established
     */
    @Override
    public boolean isReadable() {
        try {
            var con = getConnection();
            if (con.isPresent()) {
                con.get().connect();
                return true;
            }
        } catch (final IOException e) {
            log.error(e, "Could not read from URL: {}", getURL());
        }
        return false;
    }

    @Override
    public StructuredFilename getFileName() {
        return new StructuredFilename(getURL().getPath());
    }

    @Override
    public InputStream inputStream() throws IOException {
        var con = getConnection();
        if (con.isPresent()) {
            return con.get().getInputStream();
        }
        return null;
    }

    @Override
    public URL getURL() {
        return url;
    }

    @Override
    public boolean isFilesystemLoader() {
        return false;
    }

    private Optional<URLConnection> getConnection() {
        if (null == connection) {
            try {
                connection = url.openConnection();
                connection.setConnectTimeout((int) TimeUnit.SECONDS.toMillis(5));
                connection.setReadTimeout((int) TimeUnit.SECONDS.toMillis(5));
            } catch (final IOException e) {
                log.error(e, "Portal-538: Could not read from URL: {}", getURL());
            }
        }
        return Optional.ofNullable(connection);
    }
}
