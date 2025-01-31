/*
 * Copyright 2023 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.net;

import static de.cuioss.tools.string.MoreStrings.isEmpty;

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import de.cuioss.tools.string.Splitter;
import lombok.experimental.UtilityClass;
import java.util.regex.Pattern;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Provides some utility methods for url / path related data
 * 
 * @author Oliver Wolff
 * 
 */
@UtilityClass
public final class UrlHelper {

    private static final CuiLogger LOGGER = new CuiLogger(UrlHelper.class);

    /**
     * @param url to be adapted
     * @return the given url if it already suffixed with '/' or null / empty. The
     *         given url suffixed with '/' otherwise
     */
    public static String addTrailingSlashToUrl(String url) {
        if (isEmpty(url) || url.endsWith("/")) {
            return url;
        }
        return url + "/";
    }

    /**
     * @param url to be adapted
     * @return the given url if it is not suffixed with '/' or null / empty. The
     *         given url '/' removed otherwise. Multiple trailing slashes will be
     *         removed as well
     */
    public static String removeTrailingSlashesFromUrl(String url) {
        if (isEmpty(url) || !url.endsWith("/")) {
            return url;
        }
        return removeTrailingSlashesFromUrl(url.substring(0, url.length() - 1));
    }

    /**
     * @param path to be adapted
     * @return the given path if it already prefixed with '/'. The given path
     *         prefixed with '/' otherwise. In case of being null or empty it will
     *         return "/"
     */
    public static String addPrecedingSlashToPath(String path) {
        if (isEmpty(path)) {
            return "/";
        }
        if (path.startsWith("/")) {
            return path;
        }
        return "/" + path;
    }

    /**
     * @param path
     * @return the given path if it is not suffixed with '/' or null / empty. The
     *         given path '/' removed otherwise. Multiple preceding slashes will be
     *         removed as well
     */
    public static String removePrecedingSlashFromPath(String path) {
        if (isEmpty(path) || !path.startsWith("/")) {
            return path;
        }
        return removePrecedingSlashFromPath(path.substring(1));
    }

    /**
     * Split the given path String in a unified view with a list of {@link String}.
     * The individual path-elements are implicitly trimmed
     * 
     * @param pathString if it is null or empty an empty List will be returned
     * @return the list view on the path elements. never null but may be empty
     */
    public static List<String> splitPath(String pathString) {
        if (isEmpty(pathString)) {
            return Collections.emptyList();
        }
        return Splitter.on(Pattern.compile("/")).trimResults().omitEmptyStrings().splitToList(pathString);
    }

    /**
     * Split the given host String in a unified view with a list of {@link String}.
     * The individual host-elements are implicitly trimmed
     * 
     * @param host if it is null or empty an empty List will be returned
     * @return the list view on the host elements. never null but may be empty
     */
    public static List<String> splitHost(String host) {
        if (isEmpty(host)) {
            return Collections.emptyList();
        }
        return Splitter.on(Pattern.compile("\\.")).trimResults().omitEmptyStrings().splitToList(host);
    }

    /**
     * @param uri value to be verified if it is a valid URI.
     * @return URI object, if the given value is a valid URI.
     */
    public Optional<URI> tryParseUri(final String uri) {
        if (!MoreStrings.isEmpty(uri)) {
            try {
                return Optional.of(new URI(uri));
            } catch (URISyntaxException e) {
                LOGGER.trace(e, "Invalid URI");
            }
        }
        return Optional.empty();
    }

    /**
     * @param uri value to be verified if it is a valid URI.
     * @return true, if the given value is a valid URI. False otherwise.
     */
    public boolean isValidUri(final String uri) {
        if (!MoreStrings.isEmpty(uri)) {
            try {
                new URI(uri);
            } catch (URISyntaxException e) {
                return false;
            }
        }
        return true;
    }
}
