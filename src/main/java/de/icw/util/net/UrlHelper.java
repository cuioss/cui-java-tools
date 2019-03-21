package de.icw.util.net;

import static com.google.common.base.Strings.isNullOrEmpty;

/**
 * Provides some utility methods for url / path related data
 *
 * @author Oliver Wolff
 *
 */
public final class UrlHelper {

    /**
     * @param url
     * @return the given url if it already suffixed with '/' or null / empty. The given url suffixed
     *         with '/' otherwise
     */
    public static String addTrailingSlashToUrl(String url) {
        if (isNullOrEmpty(url) || url.endsWith("/")) {
            return url;
        }
        return url + "/";
    }

    /**
     * @param url
     * @return the given url if it is not suffixed with '/' or null / empty. The given url
     *         '/' removed otherwise. Multiple trailing slashes will be removed as well
     */
    public static String removeTrailingSlashesFromUrl(String url) {
        if (isNullOrEmpty(url) || !url.endsWith("/")) {
            return url;
        }
        return removeTrailingSlashesFromUrl(url.substring(0, url.length() - 1));
    }

    private UrlHelper() {
        // Utility Class
    }
}
