package de.icw.util.net;

import static de.icw.util.net.UrlHelper.addTrailingSlashToUrl;
import static de.icw.util.net.UrlHelper.removeTrailingSlashesFromUrl;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class UrlHelperTest {

    private static final String DOUBLE_SLASHED = "a/b/c//";
    private static final String SLASHED = "a/b/c/";
    private static final String NOT_SLASHED = "a/b/c";

    @Test
    void shouldAddSlashToUrls() {
        assertEquals("", addTrailingSlashToUrl(""));
        assertEquals(SLASHED, addTrailingSlashToUrl(SLASHED));
        assertEquals(SLASHED, addTrailingSlashToUrl(NOT_SLASHED));
    }

    @Test
    void shouldRemoveSlashFromUrls() {
        assertEquals("", removeTrailingSlashesFromUrl(""));
        assertEquals(NOT_SLASHED, removeTrailingSlashesFromUrl(NOT_SLASHED));
        assertEquals(NOT_SLASHED, removeTrailingSlashesFromUrl(SLASHED));
        assertEquals(NOT_SLASHED, removeTrailingSlashesFromUrl(DOUBLE_SLASHED));
    }
}
