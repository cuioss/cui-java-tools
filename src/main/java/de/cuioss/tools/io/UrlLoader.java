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

import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.TimeUnit;

import static de.cuioss.tools.base.Preconditions.checkArgument;

/**
 * This {@link FileLoader} takes a {@link URL} as its parameter which is useful
 * when e.g. iterating over an enumeration of URLs from
 * {@link ClassLoader#getResources(String)}. It converts the given URL to a
 * {@code String} and prefixes it with {@link FileTypePrefix#URL}.
 *
 * @author Sven Haag
 */
@EqualsAndHashCode(of = {"url"})
@ToString(of = {"url"})
public class UrlLoader implements FileLoader {

    @Serial
    private static final long serialVersionUID = -8758614099334823819L;

    private static final CuiLogger LOGGER = new CuiLogger(UrlLoader.class);

    private final URL url;
    private transient URLConnection connection;

    /**
     * @param url representing a valid URL
     * @throws IllegalArgumentException indicating that the given String represents
     *                                  a valid URL
     */
    public UrlLoader(final String url) {
        checkArgument(null != url, "url must not be null");
        var sanitizedUrl = url;
        if (FileTypePrefix.URL.is(url)) {
            sanitizedUrl = FileTypePrefix.URL.removePrefix(url);
        }

        try {
            this.url = URI.create(sanitizedUrl).toURL();
        } catch (final MalformedURLException | IllegalArgumentException e) {
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

    @Override
    public InputStream inputStream() throws IOException {
        if (null == connection) {
            connection = url.openConnection();
            connection.setConnectTimeout((int) TimeUnit.SECONDS.toMillis(5));
            connection.setReadTimeout((int) TimeUnit.SECONDS.toMillis(5));
        }
        return connection.getInputStream();
    }

    @Override
    public URL getURL() {
        return url;
    }

    @Override
    public boolean isReadable() {
        try {
            inputStream().close();
            return true;
        } catch (IOException e) {
            LOGGER.debug("Resource not readable: %s", url, e);
            return false;
        }
    }

    @Override
    public StructuredFilename getFileName() {
        String path = url.getPath();
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash >= 0) {
            path = path.substring(lastSlash + 1);
        }
        // Remove query parameters if present
        int queryStart = path.indexOf('?');
        if (queryStart >= 0) {
            path = path.substring(0, queryStart);
        }
        return new StructuredFilename(path);
    }

    @Override
    public boolean isFilesystemLoader() {
        return false;
    }
}
