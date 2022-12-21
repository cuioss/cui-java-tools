package io.cui.tools.io;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class UrlLoaderTest {

    @Test
    void shouldHandlePrefix() {
        assertDoesNotThrow(() -> new UrlLoader("url:file:/foo/bar"));
        assertDoesNotThrow(() -> new UrlLoader("file:/foo/bar"));
    }

    @Test
    void niceToString() {
        final String result = new UrlLoader(UrlLoaderTest.class.getResource("/someTestFile.txt")).toString();
        assertTrue(result.startsWith("UrlLoader(url=file:"));
        assertTrue(result.endsWith("someTestFile.txt)"));
    }
}
