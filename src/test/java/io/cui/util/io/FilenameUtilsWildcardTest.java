package io.cui.util.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Locale;

import org.junit.jupiter.api.Test;

/**
 * @author https://github.com/apache/commons-io/blob/master/src/test/java/org/apache/commons/io/FilenameUtilsWildcardTestCase.java
 *
 */
class FilenameUtilsWildcardTest {

    private static final boolean WINDOWS = File.separatorChar == '\\';

    @Test
    public void testMatch() {
        assertFalse(FilenameUtils.wildcardMatch(null, "Foo"));
        assertFalse(FilenameUtils.wildcardMatch("Foo", null));
        assertTrue(FilenameUtils.wildcardMatch(null, null));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "Foo"));
        assertTrue(FilenameUtils.wildcardMatch("", ""));
        assertTrue(FilenameUtils.wildcardMatch("", "*"));
        assertFalse(FilenameUtils.wildcardMatch("", "?"));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "Fo*"));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "Fo?"));
        assertTrue(FilenameUtils.wildcardMatch("Foo Bar and Catflap", "Fo*"));
        assertTrue(FilenameUtils.wildcardMatch("New Bookmarks", "N?w ?o?k??r?s"));
        assertFalse(FilenameUtils.wildcardMatch("Foo", "Bar"));
        assertTrue(FilenameUtils.wildcardMatch("Foo Bar Foo", "F*o Bar*"));
        assertTrue(FilenameUtils.wildcardMatch("Adobe Acrobat Installer", "Ad*er"));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "*Foo"));
        assertTrue(FilenameUtils.wildcardMatch("BarFoo", "*Foo"));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "Foo*"));
        assertTrue(FilenameUtils.wildcardMatch("FooBar", "Foo*"));
        assertFalse(FilenameUtils.wildcardMatch("FOO", "*Foo"));
        assertFalse(FilenameUtils.wildcardMatch("BARFOO", "*Foo"));
        assertFalse(FilenameUtils.wildcardMatch("FOO", "Foo*"));
        assertFalse(FilenameUtils.wildcardMatch("FOOBAR", "Foo*"));
    }

    @Test
    public void testMatchOnSystem() {
        assertFalse(FilenameUtils.wildcardMatchOnSystem(null, "Foo"));
        assertFalse(FilenameUtils.wildcardMatchOnSystem("Foo", null));
        assertTrue(FilenameUtils.wildcardMatchOnSystem(null, null));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("Foo", "Foo"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("", ""));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("Foo", "Fo*"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("Foo", "Fo?"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("Foo Bar and Catflap", "Fo*"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("New Bookmarks", "N?w ?o?k??r?s"));
        assertFalse(FilenameUtils.wildcardMatchOnSystem("Foo", "Bar"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("Foo Bar Foo", "F*o Bar*"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("Adobe Acrobat Installer", "Ad*er"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("Foo", "*Foo"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("BarFoo", "*Foo"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("Foo", "Foo*"));
        assertTrue(FilenameUtils.wildcardMatchOnSystem("FooBar", "Foo*"));
        assertEquals(WINDOWS, FilenameUtils.wildcardMatchOnSystem("FOO", "*Foo"));
        assertEquals(WINDOWS, FilenameUtils.wildcardMatchOnSystem("BARFOO", "*Foo"));
        assertEquals(WINDOWS, FilenameUtils.wildcardMatchOnSystem("FOO", "Foo*"));
        assertEquals(WINDOWS, FilenameUtils.wildcardMatchOnSystem("FOOBAR", "Foo*"));
    }

    @Test
    public void testMatchCaseSpecified() {
        assertFalse(FilenameUtils.wildcardMatch(null, "Foo", IOCase.SENSITIVE));
        assertFalse(FilenameUtils.wildcardMatch("Foo", null, IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch(null, null, IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "Foo", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("", "", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "Fo*", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "Fo?", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Foo Bar and Catflap", "Fo*", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("New Bookmarks", "N?w ?o?k??r?s", IOCase.SENSITIVE));
        assertFalse(FilenameUtils.wildcardMatch("Foo", "Bar", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Foo Bar Foo", "F*o Bar*", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Adobe Acrobat Installer", "Ad*er", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "*Foo", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "Foo*", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "*Foo", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("BarFoo", "*Foo", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("Foo", "Foo*", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("FooBar", "Foo*", IOCase.SENSITIVE));

        assertFalse(FilenameUtils.wildcardMatch("FOO", "*Foo", IOCase.SENSITIVE));
        assertFalse(FilenameUtils.wildcardMatch("BARFOO", "*Foo", IOCase.SENSITIVE));
        assertFalse(FilenameUtils.wildcardMatch("FOO", "Foo*", IOCase.SENSITIVE));
        assertFalse(FilenameUtils.wildcardMatch("FOOBAR", "Foo*", IOCase.SENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("FOO", "*Foo", IOCase.INSENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("BARFOO", "*Foo", IOCase.INSENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("FOO", "Foo*", IOCase.INSENSITIVE));
        assertTrue(FilenameUtils.wildcardMatch("FOOBAR", "Foo*", IOCase.INSENSITIVE));
        assertEquals(WINDOWS, FilenameUtils.wildcardMatch("FOO", "*Foo", IOCase.SYSTEM));
        assertEquals(WINDOWS, FilenameUtils.wildcardMatch("BARFOO", "*Foo", IOCase.SYSTEM));
        assertEquals(WINDOWS, FilenameUtils.wildcardMatch("FOO", "Foo*", IOCase.SYSTEM));
        assertEquals(WINDOWS, FilenameUtils.wildcardMatch("FOOBAR", "Foo*", IOCase.SYSTEM));
    }

    @Test
    public void testSplitOnTokens() {
        assertArrayEquals(new String[] { "Ad", "*", "er" }, FilenameUtils.splitOnTokens("Ad*er"));
        assertArrayEquals(new String[] { "Ad", "?", "er" }, FilenameUtils.splitOnTokens("Ad?er"));
        assertArrayEquals(new String[] { "Test", "*", "?", "One" }, FilenameUtils.splitOnTokens("Test*?One"));
        assertArrayEquals(new String[] { "Test", "?", "*", "One" }, FilenameUtils.splitOnTokens("Test?*One"));
        assertArrayEquals(new String[] { "*" }, FilenameUtils.splitOnTokens("****"));
        assertArrayEquals(new String[] { "*", "?", "?", "*" }, FilenameUtils.splitOnTokens("*??*"));
        assertArrayEquals(new String[] { "*", "?", "*", "?", "*" }, FilenameUtils.splitOnTokens("*?**?*"));
        assertArrayEquals(new String[] { "*", "?", "*", "?", "*" }, FilenameUtils.splitOnTokens("*?***?*"));
        assertArrayEquals(new String[] { "h", "?", "?", "*" }, FilenameUtils.splitOnTokens("h??*"));
        assertArrayEquals(new String[] { "" }, FilenameUtils.splitOnTokens(""));
    }

    private void assertMatch(final String text, final String wildcard, final boolean expected) {
        assertEquals(expected, FilenameUtils.wildcardMatch(text, wildcard), text + " " + wildcard);
    }

    // A separate set of tests, added to this batch
    @Test
    public void testMatch2() {
        assertMatch("log.txt", "log.txt", true);
        assertMatch("log.txt1", "log.txt", false);

        assertMatch("log.txt", "log.txt*", true);
        assertMatch("log.txt", "log.txt*1", false);
        assertMatch("log.txt", "*log.txt*", true);

        assertMatch("log.txt", "*.txt", true);
        assertMatch("txt.log", "*.txt", false);
        assertMatch("config.ini", "*.ini", true);

        assertMatch("config.txt.bak", "con*.txt", false);

        assertMatch("log.txt9", "*.txt?", true);
        assertMatch("log.txt", "*.txt?", false);

        assertMatch("progtestcase.java~5~", "*test*.java~*~", true);
        assertMatch("progtestcase.java;5~", "*test*.java~*~", false);
        assertMatch("progtestcase.java~5", "*test*.java~*~", false);

        assertMatch("log.txt", "log.*", true);

        assertMatch("log.txt", "log?*", true);

        assertMatch("log.txt12", "log.txt??", true);

        assertMatch("log.log", "log**log", true);
        assertMatch("log.log", "log**", true);
        assertMatch("log.log", "log.**", true);
        assertMatch("log.log", "**.log", true);
        assertMatch("log.log", "**log", true);

        assertMatch("log.log", "log*log", true);
        assertMatch("log.log", "log*", true);
        assertMatch("log.log", "log.*", true);
        assertMatch("log.log", "*.log", true);
        assertMatch("log.log", "*log", true);

        assertMatch("log.log", "*log?", false);
        assertMatch("log.log", "*log?*", true);
        assertMatch("log.log.abc", "*log?abc", true);
        assertMatch("log.log.abc.log.abc", "*log?abc", true);
        assertMatch("log.log.abc.log.abc.d", "*log?abc?d", true);
    }

    /**
     * See https://issues.apache.org/jira/browse/IO-246
     */
    @Test
    public void test_IO_246() {

        // Tests for "*?"
        assertMatch("aaa", "aa*?", true);

        // Tests for "?*"
        assertMatch("", "?*", false);
        assertMatch("a", "a?*", false);
        assertMatch("aa", "aa?*", false);
        assertMatch("a", "?*", true);
        assertMatch("aa", "?*", true);
        assertMatch("aaa", "?*", true);

        // Test ending on "?"
        assertMatch("", "?", false);
        assertMatch("a", "a?", false);
        assertMatch("aa", "aa?", false);
        assertMatch("aab", "aa?", true);
        assertMatch("aaa", "*a", true);
    }

    @Test
    public void testLocaleIndependence() {
        final Locale orig = Locale.getDefault();

        final Locale[] locales = Locale.getAvailableLocales();

        final String[][] data = {
            { "I", "i" },
            { "i", "I" },
            { "i", "\u0130" },
            { "i", "\u0131" },
            { "\u03A3", "\u03C2" },
            { "\u03A3", "\u03C3" },
            { "\u03C2", "\u03C3" },
        };

        try {
            for (int i = 0; i < data.length; i++) {
                for (final Locale locale : locales) {
                    Locale.setDefault(locale);
                    assertTrue(data[i][0].equalsIgnoreCase(data[i][1]), "Test data corrupt: " + i);
                    final boolean match = FilenameUtils.wildcardMatch(data[i][0], data[i][1], IOCase.INSENSITIVE);
                    assertTrue(match, Locale.getDefault().toString() + ": " + i);
                }
            }
        } finally {
            Locale.setDefault(orig);
        }
    }

}
