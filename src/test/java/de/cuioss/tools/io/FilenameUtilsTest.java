/*
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

import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author <a href="https://github.com/apache/commons-io/blob/master/src/test/java/org/apache/commons/io/FilenameUtilsTestCase.java">...</a>
 */
@SuppressWarnings("java:S5961")
// owolff: I prefer being in sync with the original test
class FilenameUtilsTest {

    private static final String SEP = "" + File.separatorChar;
    private static final boolean WINDOWS = File.separatorChar == '\\';

    @Test
    void normalize() {
        assertNull(FilenameUtils.normalize(null));
        assertNull(FilenameUtils.normalize(":"));
        assertNull(FilenameUtils.normalize("1:\\a\\b\\c.txt"));
        assertNull(FilenameUtils.normalize("1:"));
        assertNull(FilenameUtils.normalize("1:a"));
        assertNull(FilenameUtils.normalize("\\\\\\a\\b\\c.txt"));
        assertNull(FilenameUtils.normalize("\\\\a"));

        assertEquals("a" + SEP + "b" + SEP + "c.txt", FilenameUtils.normalize("a\\b/c.txt"));
        assertEquals(SEP + "a" + SEP + "b" + SEP + "c.txt", FilenameUtils.normalize("\\a\\b/c.txt"));
        assertEquals("C:" + SEP + "a" + SEP + "b" + SEP + "c.txt", FilenameUtils.normalize("C:\\a\\b/c.txt"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\server\\a\\b/c.txt"));
        assertEquals("~" + SEP + "a" + SEP + "b" + SEP + "c.txt", FilenameUtils.normalize("~\\a\\b/c.txt"));
        assertEquals("~user" + SEP + "a" + SEP + "b" + SEP + "c.txt", FilenameUtils.normalize("~user\\a\\b/c.txt"));

        assertEquals("a" + SEP + "c", FilenameUtils.normalize("a/b/../c"));
        assertEquals("c", FilenameUtils.normalize("a/b/../../c"));
        assertEquals("c" + SEP, FilenameUtils.normalize("a/b/../../c/"));
        assertNull(FilenameUtils.normalize("a/b/../../../c"));
        assertEquals("a" + SEP, FilenameUtils.normalize("a/b/.."));
        assertEquals("a" + SEP, FilenameUtils.normalize("a/b/../"));
        assertEquals("", FilenameUtils.normalize("a/b/../.."));
        assertEquals("", FilenameUtils.normalize("a/b/../../"));
        assertNull(FilenameUtils.normalize("a/b/../../.."));
        assertEquals("a" + SEP + "d", FilenameUtils.normalize("a/b/../c/../d"));
        assertEquals("a" + SEP + "d" + SEP, FilenameUtils.normalize("a/b/../c/../d/"));
        assertEquals("a" + SEP + "b" + SEP + "d", FilenameUtils.normalize("a/b//d"));
        assertEquals("a" + SEP + "b" + SEP, FilenameUtils.normalize("a/b/././."));
        assertEquals("a" + SEP + "b" + SEP, FilenameUtils.normalize("a/b/./././"));
        assertEquals("a" + SEP, FilenameUtils.normalize("./a/"));
        assertEquals("a", FilenameUtils.normalize("./a"));
        assertEquals("", FilenameUtils.normalize("./"));
        assertEquals("", FilenameUtils.normalize("."));
        assertNull(FilenameUtils.normalize("../a"));
        assertNull(FilenameUtils.normalize(".."));
        assertEquals("", FilenameUtils.normalize(""));

        assertEquals(SEP + "a", FilenameUtils.normalize("/a"));
        assertEquals(SEP + "a" + SEP, FilenameUtils.normalize("/a/"));
        assertEquals(SEP + "a" + SEP + "c", FilenameUtils.normalize("/a/b/../c"));
        assertEquals(SEP + "c", FilenameUtils.normalize("/a/b/../../c"));
        assertNull(FilenameUtils.normalize("/a/b/../../../c"));
        assertEquals(SEP + "a" + SEP, FilenameUtils.normalize("/a/b/.."));
        assertEquals(SEP, FilenameUtils.normalize("/a/b/../.."));
        assertNull(FilenameUtils.normalize("/a/b/../../.."));
        assertEquals(SEP + "a" + SEP + "d", FilenameUtils.normalize("/a/b/../c/../d"));
        assertEquals(SEP + "a" + SEP + "b" + SEP + "d", FilenameUtils.normalize("/a/b//d"));
        assertEquals(SEP + "a" + SEP + "b" + SEP, FilenameUtils.normalize("/a/b/././."));
        assertEquals(SEP + "a", FilenameUtils.normalize("/./a"));
        assertEquals(SEP, FilenameUtils.normalize("/./"));
        assertEquals(SEP, FilenameUtils.normalize("/."));
        assertNull(FilenameUtils.normalize("/../a"));
        assertNull(FilenameUtils.normalize("/.."));
        assertEquals(SEP, FilenameUtils.normalize("/"));

        assertEquals("~" + SEP + "a", FilenameUtils.normalize("~/a"));
        assertEquals("~" + SEP + "a" + SEP, FilenameUtils.normalize("~/a/"));
        assertEquals("~" + SEP + "a" + SEP + "c", FilenameUtils.normalize("~/a/b/../c"));
        assertEquals("~" + SEP + "c", FilenameUtils.normalize("~/a/b/../../c"));
        assertNull(FilenameUtils.normalize("~/a/b/../../../c"));
        assertEquals("~" + SEP + "a" + SEP, FilenameUtils.normalize("~/a/b/.."));
        assertEquals("~" + SEP, FilenameUtils.normalize("~/a/b/../.."));
        assertNull(FilenameUtils.normalize("~/a/b/../../.."));
        assertEquals("~" + SEP + "a" + SEP + "d", FilenameUtils.normalize("~/a/b/../c/../d"));
        assertEquals("~" + SEP + "a" + SEP + "b" + SEP + "d", FilenameUtils.normalize("~/a/b//d"));
        assertEquals("~" + SEP + "a" + SEP + "b" + SEP, FilenameUtils.normalize("~/a/b/././."));
        assertEquals("~" + SEP + "a", FilenameUtils.normalize("~/./a"));
        assertEquals("~" + SEP, FilenameUtils.normalize("~/./"));
        assertEquals("~" + SEP, FilenameUtils.normalize("~/."));
        assertNull(FilenameUtils.normalize("~/../a"));
        assertNull(FilenameUtils.normalize("~/.."));
        assertEquals("~" + SEP, FilenameUtils.normalize("~/"));
        assertEquals("~" + SEP, FilenameUtils.normalize("~"));

        assertEquals("~user" + SEP + "a", FilenameUtils.normalize("~user/a"));
        assertEquals("~user" + SEP + "a" + SEP, FilenameUtils.normalize("~user/a/"));
        assertEquals("~user" + SEP + "a" + SEP + "c", FilenameUtils.normalize("~user/a/b/../c"));
        assertEquals("~user" + SEP + "c", FilenameUtils.normalize("~user/a/b/../../c"));
        assertNull(FilenameUtils.normalize("~user/a/b/../../../c"));
        assertEquals("~user" + SEP + "a" + SEP, FilenameUtils.normalize("~user/a/b/.."));
        assertEquals("~user" + SEP, FilenameUtils.normalize("~user/a/b/../.."));
        assertNull(FilenameUtils.normalize("~user/a/b/../../.."));
        assertEquals("~user" + SEP + "a" + SEP + "d", FilenameUtils.normalize("~user/a/b/../c/../d"));
        assertEquals("~user" + SEP + "a" + SEP + "b" + SEP + "d", FilenameUtils.normalize("~user/a/b//d"));
        assertEquals("~user" + SEP + "a" + SEP + "b" + SEP, FilenameUtils.normalize("~user/a/b/././."));
        assertEquals("~user" + SEP + "a", FilenameUtils.normalize("~user/./a"));
        assertEquals("~user" + SEP, FilenameUtils.normalize("~user/./"));
        assertEquals("~user" + SEP, FilenameUtils.normalize("~user/."));
        assertNull(FilenameUtils.normalize("~user/../a"));
        assertNull(FilenameUtils.normalize("~user/.."));
        assertEquals("~user" + SEP, FilenameUtils.normalize("~user/"));
        assertEquals("~user" + SEP, FilenameUtils.normalize("~user"));

        assertEquals("C:" + SEP + "a", FilenameUtils.normalize("C:/a"));
        assertEquals("C:" + SEP + "a" + SEP, FilenameUtils.normalize("C:/a/"));
        assertEquals("C:" + SEP + "a" + SEP + "c", FilenameUtils.normalize("C:/a/b/../c"));
        assertEquals("C:" + SEP + "c", FilenameUtils.normalize("C:/a/b/../../c"));
        assertNull(FilenameUtils.normalize("C:/a/b/../../../c"));
        assertEquals("C:" + SEP + "a" + SEP, FilenameUtils.normalize("C:/a/b/.."));
        assertEquals("C:" + SEP, FilenameUtils.normalize("C:/a/b/../.."));
        assertNull(FilenameUtils.normalize("C:/a/b/../../.."));
        assertEquals("C:" + SEP + "a" + SEP + "d", FilenameUtils.normalize("C:/a/b/../c/../d"));
        assertEquals("C:" + SEP + "a" + SEP + "b" + SEP + "d", FilenameUtils.normalize("C:/a/b//d"));
        assertEquals("C:" + SEP + "a" + SEP + "b" + SEP, FilenameUtils.normalize("C:/a/b/././."));
        assertEquals("C:" + SEP + "a", FilenameUtils.normalize("C:/./a"));
        assertEquals("C:" + SEP, FilenameUtils.normalize("C:/./"));
        assertEquals("C:" + SEP, FilenameUtils.normalize("C:/."));
        assertNull(FilenameUtils.normalize("C:/../a"));
        assertNull(FilenameUtils.normalize("C:/.."));
        assertEquals("C:" + SEP, FilenameUtils.normalize("C:/"));

        assertEquals("C:" + "a", FilenameUtils.normalize("C:a"));
        assertEquals("C:" + "a" + SEP, FilenameUtils.normalize("C:a/"));
        assertEquals("C:" + "a" + SEP + "c", FilenameUtils.normalize("C:a/b/../c"));
        assertEquals("C:" + "c", FilenameUtils.normalize("C:a/b/../../c"));
        assertNull(FilenameUtils.normalize("C:a/b/../../../c"));
        assertEquals("C:" + "a" + SEP, FilenameUtils.normalize("C:a/b/.."));
        assertEquals("C:", FilenameUtils.normalize("C:a/b/../.."));
        assertNull(FilenameUtils.normalize("C:a/b/../../.."));
        assertEquals("C:" + "a" + SEP + "d", FilenameUtils.normalize("C:a/b/../c/../d"));
        assertEquals("C:" + "a" + SEP + "b" + SEP + "d", FilenameUtils.normalize("C:a/b//d"));
        assertEquals("C:" + "a" + SEP + "b" + SEP, FilenameUtils.normalize("C:a/b/././."));
        assertEquals("C:" + "a", FilenameUtils.normalize("C:./a"));
        assertEquals("C:", FilenameUtils.normalize("C:./"));
        assertEquals("C:", FilenameUtils.normalize("C:."));
        assertNull(FilenameUtils.normalize("C:../a"));
        assertNull(FilenameUtils.normalize("C:.."));
        assertEquals("C:", FilenameUtils.normalize("C:"));

        assertEquals(SEP + SEP + "server" + SEP + "a", FilenameUtils.normalize("//server/a"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP, FilenameUtils.normalize("//server/a/"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "c", FilenameUtils.normalize("//server/a/b/../c"));
        assertEquals(SEP + SEP + "server" + SEP + "c", FilenameUtils.normalize("//server/a/b/../../c"));
        assertNull(FilenameUtils.normalize("//server/a/b/../../../c"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP, FilenameUtils.normalize("//server/a/b/.."));
        assertEquals(SEP + SEP + "server" + SEP, FilenameUtils.normalize("//server/a/b/../.."));
        assertNull(FilenameUtils.normalize("//server/a/b/../../.."));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "d", FilenameUtils.normalize("//server/a/b/../c/../d"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "b" + SEP + "d",
                FilenameUtils.normalize("//server/a/b//d"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "b" + SEP, FilenameUtils.normalize("//server/a/b/././."));
        assertEquals(SEP + SEP + "server" + SEP + "a", FilenameUtils.normalize("//server/./a"));
        assertEquals(SEP + SEP + "server" + SEP, FilenameUtils.normalize("//server/./"));
        assertEquals(SEP + SEP + "server" + SEP, FilenameUtils.normalize("//server/."));
        assertNull(FilenameUtils.normalize("//server/../a"));
        assertNull(FilenameUtils.normalize("//server/.."));
        assertEquals(SEP + SEP + "server" + SEP, FilenameUtils.normalize("//server/"));

        assertEquals(SEP + SEP + "127.0.0.1" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\127.0.0.1\\a\\b\\c.txt"));
        assertEquals(SEP + SEP + "::1" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\::1\\a\\b\\c.txt"));
        assertEquals(SEP + SEP + "1::" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\1::\\a\\b\\c.txt"));
        assertEquals(SEP + SEP + "server.example.org" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\server.example.org\\a\\b\\c.txt"));
        assertEquals(SEP + SEP + "server.sub.example.org" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\server.sub.example.org\\a\\b\\c.txt"));
        assertEquals(SEP + SEP + "server." + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\server.\\a\\b\\c.txt"));
        assertEquals(SEP + SEP + "1::127.0.0.1" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\1::127.0.0.1\\a\\b\\c.txt"));

        // not valid IPv4 addresses but technically a valid "reg-name"s according to
        // RFC1034
        assertEquals(SEP + SEP + "127.0.0.256" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\127.0.0.256\\a\\b\\c.txt"));
        assertEquals(SEP + SEP + "127.0.0.01" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalize("\\\\127.0.0.01\\a\\b\\c.txt"));
    }

    @Test
    void shouldFailToNormalizeWithNullbytes() {
        assertThrows(IllegalArgumentException.class, () -> FilenameUtils.normalize("a\\b/c\u0000.txt"));
        assertThrows(IllegalArgumentException.class, () -> FilenameUtils.normalize("\u0000a\\b/c.txt"));

    }

    @Test
    void normalizeUnixWin() {

        // Normalize (Unix Separator)
        assertEquals("/a/c/", FilenameUtils.normalize("/a/b/../c/", true));
        assertEquals("/a/c/", FilenameUtils.normalize("\\a\\b\\..\\c\\", true));

        // Normalize (Windows Separator)
        assertEquals("\\a\\c\\", FilenameUtils.normalize("/a/b/../c/", false));
        assertEquals("\\a\\c\\", FilenameUtils.normalize("\\a\\b\\..\\c\\", false));
    }

    // -----------------------------------------------------------------------
    @Test
    void normalizeNoEndSeparator() {
        assertNull(FilenameUtils.normalizeNoEndSeparator(null));
        assertNull(FilenameUtils.normalizeNoEndSeparator(":"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("1:\\a\\b\\c.txt"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("1:"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("1:a"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("\\\\\\a\\b\\c.txt"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("\\\\a"));

        assertEquals("a" + SEP + "b" + SEP + "c.txt", FilenameUtils.normalizeNoEndSeparator("a\\b/c.txt"));
        assertEquals(SEP + "a" + SEP + "b" + SEP + "c.txt", FilenameUtils.normalizeNoEndSeparator("\\a\\b/c.txt"));
        assertEquals("C:" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalizeNoEndSeparator("C:\\a\\b/c.txt"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalizeNoEndSeparator("\\\\server\\a\\b/c.txt"));
        assertEquals("~" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalizeNoEndSeparator("~\\a\\b/c.txt"));
        assertEquals("~user" + SEP + "a" + SEP + "b" + SEP + "c.txt",
                FilenameUtils.normalizeNoEndSeparator("~user\\a\\b/c.txt"));

        assertEquals("a" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("a/b/../c"));
        assertEquals("c", FilenameUtils.normalizeNoEndSeparator("a/b/../../c"));
        assertEquals("c", FilenameUtils.normalizeNoEndSeparator("a/b/../../c/"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("a/b/../../../c"));
        assertEquals("a", FilenameUtils.normalizeNoEndSeparator("a/b/.."));
        assertEquals("a", FilenameUtils.normalizeNoEndSeparator("a/b/../"));
        assertEquals("", FilenameUtils.normalizeNoEndSeparator("a/b/../.."));
        assertEquals("", FilenameUtils.normalizeNoEndSeparator("a/b/../../"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("a/b/../../.."));
        assertEquals("a" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("a/b/../c/../d"));
        assertEquals("a" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("a/b/../c/../d/"));
        assertEquals("a" + SEP + "b" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("a/b//d"));
        assertEquals("a" + SEP + "b", FilenameUtils.normalizeNoEndSeparator("a/b/././."));
        assertEquals("a" + SEP + "b", FilenameUtils.normalizeNoEndSeparator("a/b/./././"));
        assertEquals("a", FilenameUtils.normalizeNoEndSeparator("./a/"));
        assertEquals("a", FilenameUtils.normalizeNoEndSeparator("./a"));
        assertEquals("", FilenameUtils.normalizeNoEndSeparator("./"));
        assertEquals("", FilenameUtils.normalizeNoEndSeparator("."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("../a"));
        assertNull(FilenameUtils.normalizeNoEndSeparator(".."));
        assertEquals("", FilenameUtils.normalizeNoEndSeparator(""));

        assertEquals(SEP + "a", FilenameUtils.normalizeNoEndSeparator("/a"));
        assertEquals(SEP + "a", FilenameUtils.normalizeNoEndSeparator("/a/"));
        assertEquals(SEP + "a" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("/a/b/../c"));
        assertEquals(SEP + "c", FilenameUtils.normalizeNoEndSeparator("/a/b/../../c"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("/a/b/../../../c"));
        assertEquals(SEP + "a", FilenameUtils.normalizeNoEndSeparator("/a/b/.."));
        assertEquals(SEP, FilenameUtils.normalizeNoEndSeparator("/a/b/../.."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("/a/b/../../.."));
        assertEquals(SEP + "a" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("/a/b/../c/../d"));
        assertEquals(SEP + "a" + SEP + "b" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("/a/b//d"));
        assertEquals(SEP + "a" + SEP + "b", FilenameUtils.normalizeNoEndSeparator("/a/b/././."));
        assertEquals(SEP + "a", FilenameUtils.normalizeNoEndSeparator("/./a"));
        assertEquals(SEP, FilenameUtils.normalizeNoEndSeparator("/./"));
        assertEquals(SEP, FilenameUtils.normalizeNoEndSeparator("/."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("/../a"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("/.."));
        assertEquals(SEP, FilenameUtils.normalizeNoEndSeparator("/"));

        assertEquals("~" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("~/a"));
        assertEquals("~" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("~/a/"));
        assertEquals("~" + SEP + "a" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("~/a/b/../c"));
        assertEquals("~" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("~/a/b/../../c"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("~/a/b/../../../c"));
        assertEquals("~" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("~/a/b/.."));
        assertEquals("~" + SEP, FilenameUtils.normalizeNoEndSeparator("~/a/b/../.."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("~/a/b/../../.."));
        assertEquals("~" + SEP + "a" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("~/a/b/../c/../d"));
        assertEquals("~" + SEP + "a" + SEP + "b" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("~/a/b//d"));
        assertEquals("~" + SEP + "a" + SEP + "b", FilenameUtils.normalizeNoEndSeparator("~/a/b/././."));
        assertEquals("~" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("~/./a"));
        assertEquals("~" + SEP, FilenameUtils.normalizeNoEndSeparator("~/./"));
        assertEquals("~" + SEP, FilenameUtils.normalizeNoEndSeparator("~/."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("~/../a"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("~/.."));
        assertEquals("~" + SEP, FilenameUtils.normalizeNoEndSeparator("~/"));
        assertEquals("~" + SEP, FilenameUtils.normalizeNoEndSeparator("~"));

        assertEquals("~user" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("~user/a"));
        assertEquals("~user" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("~user/a/"));
        assertEquals("~user" + SEP + "a" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("~user/a/b/../c"));
        assertEquals("~user" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("~user/a/b/../../c"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("~user/a/b/../../../c"));
        assertEquals("~user" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("~user/a/b/.."));
        assertEquals("~user" + SEP, FilenameUtils.normalizeNoEndSeparator("~user/a/b/../.."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("~user/a/b/../../.."));
        assertEquals("~user" + SEP + "a" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("~user/a/b/../c/../d"));
        assertEquals("~user" + SEP + "a" + SEP + "b" + SEP + "d",
                FilenameUtils.normalizeNoEndSeparator("~user/a/b//d"));
        assertEquals("~user" + SEP + "a" + SEP + "b", FilenameUtils.normalizeNoEndSeparator("~user/a/b/././."));
        assertEquals("~user" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("~user/./a"));
        assertEquals("~user" + SEP, FilenameUtils.normalizeNoEndSeparator("~user/./"));
        assertEquals("~user" + SEP, FilenameUtils.normalizeNoEndSeparator("~user/."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("~user/../a"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("~user/.."));
        assertEquals("~user" + SEP, FilenameUtils.normalizeNoEndSeparator("~user/"));
        assertEquals("~user" + SEP, FilenameUtils.normalizeNoEndSeparator("~user"));

        assertEquals("C:" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("C:/a"));
        assertEquals("C:" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("C:/a/"));
        assertEquals("C:" + SEP + "a" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("C:/a/b/../c"));
        assertEquals("C:" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("C:/a/b/../../c"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("C:/a/b/../../../c"));
        assertEquals("C:" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("C:/a/b/.."));
        assertEquals("C:" + SEP, FilenameUtils.normalizeNoEndSeparator("C:/a/b/../.."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("C:/a/b/../../.."));
        assertEquals("C:" + SEP + "a" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("C:/a/b/../c/../d"));
        assertEquals("C:" + SEP + "a" + SEP + "b" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("C:/a/b//d"));
        assertEquals("C:" + SEP + "a" + SEP + "b", FilenameUtils.normalizeNoEndSeparator("C:/a/b/././."));
        assertEquals("C:" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("C:/./a"));
        assertEquals("C:" + SEP, FilenameUtils.normalizeNoEndSeparator("C:/./"));
        assertEquals("C:" + SEP, FilenameUtils.normalizeNoEndSeparator("C:/."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("C:/../a"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("C:/.."));
        assertEquals("C:" + SEP, FilenameUtils.normalizeNoEndSeparator("C:/"));

        assertEquals("C:" + "a", FilenameUtils.normalizeNoEndSeparator("C:a"));
        assertEquals("C:" + "a", FilenameUtils.normalizeNoEndSeparator("C:a/"));
        assertEquals("C:" + "a" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("C:a/b/../c"));
        assertEquals("C:" + "c", FilenameUtils.normalizeNoEndSeparator("C:a/b/../../c"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("C:a/b/../../../c"));
        assertEquals("C:" + "a", FilenameUtils.normalizeNoEndSeparator("C:a/b/.."));
        assertEquals("C:", FilenameUtils.normalizeNoEndSeparator("C:a/b/../.."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("C:a/b/../../.."));
        assertEquals("C:" + "a" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("C:a/b/../c/../d"));
        assertEquals("C:" + "a" + SEP + "b" + SEP + "d", FilenameUtils.normalizeNoEndSeparator("C:a/b//d"));
        assertEquals("C:" + "a" + SEP + "b", FilenameUtils.normalizeNoEndSeparator("C:a/b/././."));
        assertEquals("C:" + "a", FilenameUtils.normalizeNoEndSeparator("C:./a"));
        assertEquals("C:", FilenameUtils.normalizeNoEndSeparator("C:./"));
        assertEquals("C:", FilenameUtils.normalizeNoEndSeparator("C:."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("C:../a"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("C:.."));
        assertEquals("C:", FilenameUtils.normalizeNoEndSeparator("C:"));

        assertEquals(SEP + SEP + "server" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("//server/a"));
        assertEquals(SEP + SEP + "server" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("//server/a/"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "c",
                FilenameUtils.normalizeNoEndSeparator("//server/a/b/../c"));
        assertEquals(SEP + SEP + "server" + SEP + "c", FilenameUtils.normalizeNoEndSeparator("//server/a/b/../../c"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("//server/a/b/../../../c"));
        assertEquals(SEP + SEP + "server" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("//server/a/b/.."));
        assertEquals(SEP + SEP + "server" + SEP, FilenameUtils.normalizeNoEndSeparator("//server/a/b/../.."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("//server/a/b/../../.."));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "d",
                FilenameUtils.normalizeNoEndSeparator("//server/a/b/../c/../d"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "b" + SEP + "d",
                FilenameUtils.normalizeNoEndSeparator("//server/a/b//d"));
        assertEquals(SEP + SEP + "server" + SEP + "a" + SEP + "b",
                FilenameUtils.normalizeNoEndSeparator("//server/a/b/././."));
        assertEquals(SEP + SEP + "server" + SEP + "a", FilenameUtils.normalizeNoEndSeparator("//server/./a"));
        assertEquals(SEP + SEP + "server" + SEP, FilenameUtils.normalizeNoEndSeparator("//server/./"));
        assertEquals(SEP + SEP + "server" + SEP, FilenameUtils.normalizeNoEndSeparator("//server/."));
        assertNull(FilenameUtils.normalizeNoEndSeparator("//server/../a"));
        assertNull(FilenameUtils.normalizeNoEndSeparator("//server/.."));
        assertEquals(SEP + SEP + "server" + SEP, FilenameUtils.normalizeNoEndSeparator("//server/"));
    }

    @Test
    void normalizeNoEndSeparatorUnixWin() {

        // Normalize (Unix Separator)
        assertEquals("/a/c", FilenameUtils.normalizeNoEndSeparator("/a/b/../c/", true));
        assertEquals("/a/c", FilenameUtils.normalizeNoEndSeparator("\\a\\b\\..\\c\\", true));

        // Normalize (Windows Separator)
        assertEquals("\\a\\c", FilenameUtils.normalizeNoEndSeparator("/a/b/../c/", false));
        assertEquals("\\a\\c", FilenameUtils.normalizeNoEndSeparator("\\a\\b\\..\\c\\", false));
    }

    // -----------------------------------------------------------------------
    @Test
    void concat() {
        assertNull(FilenameUtils.concat("", null));
        assertNull(FilenameUtils.concat(null, null));
        assertNull(FilenameUtils.concat(null, ""));
        assertNull(FilenameUtils.concat(null, "a"));
        assertEquals(SEP + "a", FilenameUtils.concat(null, "/a"));

        assertNull(FilenameUtils.concat("", ":")); // invalid prefix
        assertNull(FilenameUtils.concat(":", "")); // invalid prefix

        assertEquals("f" + SEP, FilenameUtils.concat("", "f/"));
        assertEquals("f", FilenameUtils.concat("", "f"));
        assertEquals("a" + SEP + "f" + SEP, FilenameUtils.concat("a/", "f/"));
        assertEquals("a" + SEP + "f", FilenameUtils.concat("a", "f"));
        assertEquals("a" + SEP + "b" + SEP + "f" + SEP, FilenameUtils.concat("a/b/", "f/"));
        assertEquals("a" + SEP + "b" + SEP + "f", FilenameUtils.concat("a/b", "f"));

        assertEquals("a" + SEP + "f" + SEP, FilenameUtils.concat("a/b/", "../f/"));
        assertEquals("a" + SEP + "f", FilenameUtils.concat("a/b", "../f"));
        assertEquals("a" + SEP + "c" + SEP + "g" + SEP, FilenameUtils.concat("a/b/../c/", "f/../g/"));
        assertEquals("a" + SEP + "c" + SEP + "g", FilenameUtils.concat("a/b/../c", "f/../g"));

        assertEquals("a" + SEP + "c.txt" + SEP + "f", FilenameUtils.concat("a/c.txt", "f"));

        assertEquals(SEP + "f" + SEP, FilenameUtils.concat("", "/f/"));
        assertEquals(SEP + "f", FilenameUtils.concat("", "/f"));
        assertEquals(SEP + "f" + SEP, FilenameUtils.concat("a/", "/f/"));
        assertEquals(SEP + "f", FilenameUtils.concat("a", "/f"));

        assertEquals(SEP + "c" + SEP + "d", FilenameUtils.concat("a/b/", "/c/d"));
        assertEquals("C:c" + SEP + "d", FilenameUtils.concat("a/b/", "C:c/d"));
        assertEquals("C:" + SEP + "c" + SEP + "d", FilenameUtils.concat("a/b/", "C:/c/d"));
        assertEquals("~" + SEP + "c" + SEP + "d", FilenameUtils.concat("a/b/", "~/c/d"));
        assertEquals("~user" + SEP + "c" + SEP + "d", FilenameUtils.concat("a/b/", "~user/c/d"));
        assertEquals("~" + SEP, FilenameUtils.concat("a/b/", "~"));
        assertEquals("~user" + SEP, FilenameUtils.concat("a/b/", "~user"));
    }

    // -----------------------------------------------------------------------
    @Test
    void separatorsToUnix() {
        assertNull(FilenameUtils.separatorsToUnix(null));
        assertEquals("/a/b/c", FilenameUtils.separatorsToUnix("/a/b/c"));
        assertEquals("/a/b/c.txt", FilenameUtils.separatorsToUnix("/a/b/c.txt"));
        assertEquals("/a/b/c", FilenameUtils.separatorsToUnix("/a/b\\c"));
        assertEquals("/a/b/c", FilenameUtils.separatorsToUnix("\\a\\b\\c"));
        assertEquals("D:/a/b/c", FilenameUtils.separatorsToUnix("D:\\a\\b\\c"));
    }

    @Test
    void separatorsToWindows() {
        assertNull(FilenameUtils.separatorsToWindows(null));
        assertEquals("\\a\\b\\c", FilenameUtils.separatorsToWindows("\\a\\b\\c"));
        assertEquals("\\a\\b\\c.txt", FilenameUtils.separatorsToWindows("\\a\\b\\c.txt"));
        assertEquals("\\a\\b\\c", FilenameUtils.separatorsToWindows("\\a\\b/c"));
        assertEquals("\\a\\b\\c", FilenameUtils.separatorsToWindows("/a/b/c"));
        assertEquals("D:\\a\\b\\c", FilenameUtils.separatorsToWindows("D:/a/b/c"));
    }

    @Test
    void separatorsToSystem() {
        if (WINDOWS) {
            assertNull(FilenameUtils.separatorsToSystem(null));
            assertEquals("\\a\\b\\c", FilenameUtils.separatorsToSystem("\\a\\b\\c"));
            assertEquals("\\a\\b\\c.txt", FilenameUtils.separatorsToSystem("\\a\\b\\c.txt"));
            assertEquals("\\a\\b\\c", FilenameUtils.separatorsToSystem("\\a\\b/c"));
            assertEquals("\\a\\b\\c", FilenameUtils.separatorsToSystem("/a/b/c"));
            assertEquals("D:\\a\\b\\c", FilenameUtils.separatorsToSystem("D:/a/b/c"));
        } else {
            assertNull(FilenameUtils.separatorsToSystem(null));
            assertEquals("/a/b/c", FilenameUtils.separatorsToSystem("/a/b/c"));
            assertEquals("/a/b/c.txt", FilenameUtils.separatorsToSystem("/a/b/c.txt"));
            assertEquals("/a/b/c", FilenameUtils.separatorsToSystem("/a/b\\c"));
            assertEquals("/a/b/c", FilenameUtils.separatorsToSystem("\\a\\b\\c"));
            assertEquals("D:/a/b/c", FilenameUtils.separatorsToSystem("D:\\a\\b\\c"));
        }
    }

    // -----------------------------------------------------------------------
    @Test
    void getPrefixLength() {
        assertEquals(-1, FilenameUtils.getPrefixLength(null));
        assertEquals(-1, FilenameUtils.getPrefixLength(":"));
        assertEquals(-1, FilenameUtils.getPrefixLength("1:\\a\\b\\c.txt"));
        assertEquals(-1, FilenameUtils.getPrefixLength("1:"));
        assertEquals(-1, FilenameUtils.getPrefixLength("1:a"));
        assertEquals(-1, FilenameUtils.getPrefixLength("\\\\\\a\\b\\c.txt"));
        assertEquals(-1, FilenameUtils.getPrefixLength("\\\\a"));

        assertEquals(0, FilenameUtils.getPrefixLength(""));
        assertEquals(1, FilenameUtils.getPrefixLength("\\"));
        assertEquals(2, FilenameUtils.getPrefixLength("C:"));
        assertEquals(3, FilenameUtils.getPrefixLength("C:\\"));
        assertEquals(9, FilenameUtils.getPrefixLength("//server/"));
        assertEquals(2, FilenameUtils.getPrefixLength("~"));
        assertEquals(2, FilenameUtils.getPrefixLength("~/"));
        assertEquals(6, FilenameUtils.getPrefixLength("~user"));
        assertEquals(6, FilenameUtils.getPrefixLength("~user/"));

        assertEquals(0, FilenameUtils.getPrefixLength("a\\b\\c.txt"));
        assertEquals(1, FilenameUtils.getPrefixLength("\\a\\b\\c.txt"));
        assertEquals(2, FilenameUtils.getPrefixLength("C:a\\b\\c.txt"));
        assertEquals(3, FilenameUtils.getPrefixLength("C:\\a\\b\\c.txt"));
        assertEquals(9, FilenameUtils.getPrefixLength("\\\\server\\a\\b\\c.txt"));

        assertEquals(0, FilenameUtils.getPrefixLength("a/b/c.txt"));
        assertEquals(1, FilenameUtils.getPrefixLength("/a/b/c.txt"));
        assertEquals(3, FilenameUtils.getPrefixLength("C:/a/b/c.txt"));
        assertEquals(9, FilenameUtils.getPrefixLength("//server/a/b/c.txt"));
        assertEquals(2, FilenameUtils.getPrefixLength("~/a/b/c.txt"));
        assertEquals(6, FilenameUtils.getPrefixLength("~user/a/b/c.txt"));

        assertEquals(0, FilenameUtils.getPrefixLength("a\\b\\c.txt"));
        assertEquals(1, FilenameUtils.getPrefixLength("\\a\\b\\c.txt"));
        assertEquals(2, FilenameUtils.getPrefixLength("~\\a\\b\\c.txt"));
        assertEquals(6, FilenameUtils.getPrefixLength("~user\\a\\b\\c.txt"));

        assertEquals(9, FilenameUtils.getPrefixLength("//server/a/b/c.txt"));
        assertEquals(-1, FilenameUtils.getPrefixLength("\\\\\\a\\b\\c.txt"));
        assertEquals(-1, FilenameUtils.getPrefixLength("///a/b/c.txt"));

        assertEquals(1, FilenameUtils.getPrefixLength("/:foo"));
        assertEquals(1, FilenameUtils.getPrefixLength("/:/"));
        assertEquals(1, FilenameUtils.getPrefixLength("/:::::::.txt"));

        assertEquals(12, FilenameUtils.getPrefixLength("\\\\127.0.0.1\\a\\b\\c.txt"));
        assertEquals(6, FilenameUtils.getPrefixLength("\\\\::1\\a\\b\\c.txt"));
        assertEquals(21, FilenameUtils.getPrefixLength("\\\\server.example.org\\a\\b\\c.txt"));
        assertEquals(10, FilenameUtils.getPrefixLength("\\\\server.\\a\\b\\c.txt"));

    }

    @Test
    void indexOfLastSeparator() {
        assertEquals(-1, FilenameUtils.indexOfLastSeparator(null));
        assertEquals(-1, FilenameUtils.indexOfLastSeparator("noseperator.inthispath"));
        assertEquals(3, FilenameUtils.indexOfLastSeparator("a/b/c"));
        assertEquals(3, FilenameUtils.indexOfLastSeparator("a\\b\\c"));
    }

    @Test
    void indexOfExtension() {
        assertEquals(-1, FilenameUtils.indexOfExtension(null));
        assertEquals(-1, FilenameUtils.indexOfExtension("file"));
        assertEquals(4, FilenameUtils.indexOfExtension("file.txt"));
        assertEquals(13, FilenameUtils.indexOfExtension("a.txt/b.txt/c.txt"));
        assertEquals(-1, FilenameUtils.indexOfExtension("a/b/c"));
        assertEquals(-1, FilenameUtils.indexOfExtension("a\\b\\c"));
        assertEquals(-1, FilenameUtils.indexOfExtension("a/b.notextension/c"));
        assertEquals(-1, FilenameUtils.indexOfExtension("a\\b.notextension\\c"));

        assertEquals(11, FilenameUtils.indexOfExtension("foo.exe:bar.txt"));
    }

    // -----------------------------------------------------------------------
    @Test
    void getPrefix() {
        assertNull(FilenameUtils.getPrefix(null));
        assertNull(FilenameUtils.getPrefix(":"));
        assertNull(FilenameUtils.getPrefix("1:\\a\\b\\c.txt"));
        assertNull(FilenameUtils.getPrefix("1:"));
        assertNull(FilenameUtils.getPrefix("1:a"));
        assertNull(FilenameUtils.getPrefix("\\\\\\a\\b\\c.txt"));
        assertNull(FilenameUtils.getPrefix("\\\\a"));

        assertEquals("", FilenameUtils.getPrefix(""));
        assertEquals("\\", FilenameUtils.getPrefix("\\"));
        assertEquals("C:", FilenameUtils.getPrefix("C:"));
        assertEquals("C:\\", FilenameUtils.getPrefix("C:\\"));
        assertEquals("//server/", FilenameUtils.getPrefix("//server/"));
        assertEquals("~/", FilenameUtils.getPrefix("~"));
        assertEquals("~/", FilenameUtils.getPrefix("~/"));
        assertEquals("~user/", FilenameUtils.getPrefix("~user"));
        assertEquals("~user/", FilenameUtils.getPrefix("~user/"));

        assertEquals("", FilenameUtils.getPrefix("a\\b\\c.txt"));
        assertEquals("\\", FilenameUtils.getPrefix("\\a\\b\\c.txt"));
        assertEquals("C:\\", FilenameUtils.getPrefix("C:\\a\\b\\c.txt"));
        assertEquals("\\\\server\\", FilenameUtils.getPrefix("\\\\server\\a\\b\\c.txt"));

        assertEquals("", FilenameUtils.getPrefix("a/b/c.txt"));
        assertEquals("/", FilenameUtils.getPrefix("/a/b/c.txt"));
        assertEquals("C:/", FilenameUtils.getPrefix("C:/a/b/c.txt"));
        assertEquals("//server/", FilenameUtils.getPrefix("//server/a/b/c.txt"));
        assertEquals("~/", FilenameUtils.getPrefix("~/a/b/c.txt"));
        assertEquals("~user/", FilenameUtils.getPrefix("~user/a/b/c.txt"));

        assertEquals("", FilenameUtils.getPrefix("a\\b\\c.txt"));
        assertEquals("\\", FilenameUtils.getPrefix("\\a\\b\\c.txt"));
        assertEquals("~\\", FilenameUtils.getPrefix("~\\a\\b\\c.txt"));
        assertEquals("~user\\", FilenameUtils.getPrefix("~user\\a\\b\\c.txt"));
    }

    @Test
    void shouldFailGetPrefixWithNullbyte() {
        assertThrows(IllegalArgumentException.class, () -> FilenameUtils.getPrefix("~u\u0000ser\\a\\b\\c.txt"));
    }

    @Test
    void getPath() {
        assertNull(FilenameUtils.getPath(null));
        assertEquals("", FilenameUtils.getPath("noseperator.inthispath"));
        assertEquals("", FilenameUtils.getPath("/noseperator.inthispath"));
        assertEquals("", FilenameUtils.getPath("\\noseperator.inthispath"));
        assertEquals("a/b/", FilenameUtils.getPath("a/b/c.txt"));
        assertEquals("a/b/", FilenameUtils.getPath("a/b/c"));
        assertEquals("a/b/c/", FilenameUtils.getPath("a/b/c/"));
        assertEquals("a\\b\\", FilenameUtils.getPath("a\\b\\c"));

        assertNull(FilenameUtils.getPath(":"));
        assertNull(FilenameUtils.getPath("1:/a/b/c.txt"));
        assertNull(FilenameUtils.getPath("1:"));
        assertNull(FilenameUtils.getPath("1:a"));
        assertNull(FilenameUtils.getPath("///a/b/c.txt"));
        assertNull(FilenameUtils.getPath("//a"));

        assertEquals("", FilenameUtils.getPath(""));
        assertEquals("", FilenameUtils.getPath("C:"));
        assertEquals("", FilenameUtils.getPath("C:/"));
        assertEquals("", FilenameUtils.getPath("//server/"));
        assertEquals("", FilenameUtils.getPath("~"));
        assertEquals("", FilenameUtils.getPath("~/"));
        assertEquals("", FilenameUtils.getPath("~user"));
        assertEquals("", FilenameUtils.getPath("~user/"));

        assertEquals("a/b/", FilenameUtils.getPath("a/b/c.txt"));
        assertEquals("a/b/", FilenameUtils.getPath("/a/b/c.txt"));
        assertEquals("", FilenameUtils.getPath("C:a"));
        assertEquals("a/b/", FilenameUtils.getPath("C:a/b/c.txt"));
        assertEquals("a/b/", FilenameUtils.getPath("C:/a/b/c.txt"));
        assertEquals("a/b/", FilenameUtils.getPath("//server/a/b/c.txt"));
        assertEquals("a/b/", FilenameUtils.getPath("~/a/b/c.txt"));
        assertEquals("a/b/", FilenameUtils.getPath("~user/a/b/c.txt"));
    }

    @Test
    void getPathWithNullbyte() {
        assertThrows(IllegalArgumentException.class, () ->
                FilenameUtils.getPath("~user/a/\u0000b/c.txt"));
    }

    @Test
    void getPathNoEndSeparator() {
        assertNull(FilenameUtils.getPath(null));
        assertEquals("", FilenameUtils.getPath("noseperator.inthispath"));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("/noseperator.inthispath"));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("\\noseperator.inthispath"));
        assertEquals("a/b", FilenameUtils.getPathNoEndSeparator("a/b/c.txt"));
        assertEquals("a/b", FilenameUtils.getPathNoEndSeparator("a/b/c"));
        assertEquals("a/b/c", FilenameUtils.getPathNoEndSeparator("a/b/c/"));
        assertEquals("a\\b", FilenameUtils.getPathNoEndSeparator("a\\b\\c"));

        assertNull(FilenameUtils.getPathNoEndSeparator(":"));
        assertNull(FilenameUtils.getPathNoEndSeparator("1:/a/b/c.txt"));
        assertNull(FilenameUtils.getPathNoEndSeparator("1:"));
        assertNull(FilenameUtils.getPathNoEndSeparator("1:a"));
        assertNull(FilenameUtils.getPathNoEndSeparator("///a/b/c.txt"));
        assertNull(FilenameUtils.getPathNoEndSeparator("//a"));

        assertEquals("", FilenameUtils.getPathNoEndSeparator(""));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("C:"));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("C:/"));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("//server/"));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("~"));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("~/"));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("~user"));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("~user/"));

        assertEquals("a/b", FilenameUtils.getPathNoEndSeparator("a/b/c.txt"));
        assertEquals("a/b", FilenameUtils.getPathNoEndSeparator("/a/b/c.txt"));
        assertEquals("", FilenameUtils.getPathNoEndSeparator("C:a"));
        assertEquals("a/b", FilenameUtils.getPathNoEndSeparator("C:a/b/c.txt"));
        assertEquals("a/b", FilenameUtils.getPathNoEndSeparator("C:/a/b/c.txt"));
        assertEquals("a/b", FilenameUtils.getPathNoEndSeparator("//server/a/b/c.txt"));
        assertEquals("a/b", FilenameUtils.getPathNoEndSeparator("~/a/b/c.txt"));
        assertEquals("a/b", FilenameUtils.getPathNoEndSeparator("~user/a/b/c.txt"));
    }

    @Test
    void shouldFailGetPathNoEndSeparatorWithNullByte() {
        assertThrows(IllegalArgumentException.class, () -> FilenameUtils.getPathNoEndSeparator("~user/a\u0000/b/c.txt"));
    }

    @Test
    void getFullPath() {
        assertNull(FilenameUtils.getFullPath(null));
        assertEquals("", FilenameUtils.getFullPath("noseperator.inthispath"));
        assertEquals("a/b/", FilenameUtils.getFullPath("a/b/c.txt"));
        assertEquals("a/b/", FilenameUtils.getFullPath("a/b/c"));
        assertEquals("a/b/c/", FilenameUtils.getFullPath("a/b/c/"));
        assertEquals("a\\b\\", FilenameUtils.getFullPath("a\\b\\c"));

        assertNull(FilenameUtils.getFullPath(":"));
        assertNull(FilenameUtils.getFullPath("1:/a/b/c.txt"));
        assertNull(FilenameUtils.getFullPath("1:"));
        assertNull(FilenameUtils.getFullPath("1:a"));
        assertNull(FilenameUtils.getFullPath("///a/b/c.txt"));
        assertNull(FilenameUtils.getFullPath("//a"));

        assertEquals("", FilenameUtils.getFullPath(""));
        assertEquals("C:", FilenameUtils.getFullPath("C:"));
        assertEquals("C:/", FilenameUtils.getFullPath("C:/"));
        assertEquals("//server/", FilenameUtils.getFullPath("//server/"));
        assertEquals("~/", FilenameUtils.getFullPath("~"));
        assertEquals("~/", FilenameUtils.getFullPath("~/"));
        assertEquals("~user/", FilenameUtils.getFullPath("~user"));
        assertEquals("~user/", FilenameUtils.getFullPath("~user/"));

        assertEquals("a/b/", FilenameUtils.getFullPath("a/b/c.txt"));
        assertEquals("/a/b/", FilenameUtils.getFullPath("/a/b/c.txt"));
        assertEquals("C:", FilenameUtils.getFullPath("C:a"));
        assertEquals("C:a/b/", FilenameUtils.getFullPath("C:a/b/c.txt"));
        assertEquals("C:/a/b/", FilenameUtils.getFullPath("C:/a/b/c.txt"));
        assertEquals("//server/a/b/", FilenameUtils.getFullPath("//server/a/b/c.txt"));
        assertEquals("~/a/b/", FilenameUtils.getFullPath("~/a/b/c.txt"));
        assertEquals("~user/a/b/", FilenameUtils.getFullPath("~user/a/b/c.txt"));
    }

    @Test
    void getFullPathNoEndSeparator() {
        assertNull(FilenameUtils.getFullPathNoEndSeparator(null));
        assertEquals("", FilenameUtils.getFullPathNoEndSeparator("noseperator.inthispath"));
        assertEquals("a/b", FilenameUtils.getFullPathNoEndSeparator("a/b/c.txt"));
        assertEquals("a/b", FilenameUtils.getFullPathNoEndSeparator("a/b/c"));
        assertEquals("a/b/c", FilenameUtils.getFullPathNoEndSeparator("a/b/c/"));
        assertEquals("a\\b", FilenameUtils.getFullPathNoEndSeparator("a\\b\\c"));

        assertNull(FilenameUtils.getFullPathNoEndSeparator(":"));
        assertNull(FilenameUtils.getFullPathNoEndSeparator("1:/a/b/c.txt"));
        assertNull(FilenameUtils.getFullPathNoEndSeparator("1:"));
        assertNull(FilenameUtils.getFullPathNoEndSeparator("1:a"));
        assertNull(FilenameUtils.getFullPathNoEndSeparator("///a/b/c.txt"));
        assertNull(FilenameUtils.getFullPathNoEndSeparator("//a"));

        assertEquals("", FilenameUtils.getFullPathNoEndSeparator(""));
        assertEquals("C:", FilenameUtils.getFullPathNoEndSeparator("C:"));
        assertEquals("C:/", FilenameUtils.getFullPathNoEndSeparator("C:/"));
        assertEquals("//server/", FilenameUtils.getFullPathNoEndSeparator("//server/"));
        assertEquals("~", FilenameUtils.getFullPathNoEndSeparator("~"));
        assertEquals("~/", FilenameUtils.getFullPathNoEndSeparator("~/"));
        assertEquals("~user", FilenameUtils.getFullPathNoEndSeparator("~user"));
        assertEquals("~user/", FilenameUtils.getFullPathNoEndSeparator("~user/"));

        assertEquals("a/b", FilenameUtils.getFullPathNoEndSeparator("a/b/c.txt"));
        assertEquals("/a/b", FilenameUtils.getFullPathNoEndSeparator("/a/b/c.txt"));
        assertEquals("C:", FilenameUtils.getFullPathNoEndSeparator("C:a"));
        assertEquals("C:a/b", FilenameUtils.getFullPathNoEndSeparator("C:a/b/c.txt"));
        assertEquals("C:/a/b", FilenameUtils.getFullPathNoEndSeparator("C:/a/b/c.txt"));
        assertEquals("//server/a/b", FilenameUtils.getFullPathNoEndSeparator("//server/a/b/c.txt"));
        assertEquals("~/a/b", FilenameUtils.getFullPathNoEndSeparator("~/a/b/c.txt"));
        assertEquals("~user/a/b", FilenameUtils.getFullPathNoEndSeparator("~user/a/b/c.txt"));
    }

    /**
     * Test for <a href="https://issues.apache.org/jira/browse/IO-248">...</a>
     */
    @Test
    void getFullPathNoEndSeparatorIO248() {

        // Test single separator
        assertEquals("/", FilenameUtils.getFullPathNoEndSeparator("/"));
        assertEquals("\\", FilenameUtils.getFullPathNoEndSeparator("\\"));

        // Test one level directory
        assertEquals("/", FilenameUtils.getFullPathNoEndSeparator("/abc"));
        assertEquals("\\", FilenameUtils.getFullPathNoEndSeparator("\\abc"));

        // Test one level directory
        assertEquals("/abc", FilenameUtils.getFullPathNoEndSeparator("/abc/xyz"));
        assertEquals("\\abc", FilenameUtils.getFullPathNoEndSeparator("\\abc\\xyz"));
    }

    @Test
    void getName() {
        assertNull(FilenameUtils.getName(null));
        assertEquals("noseperator.inthispath", FilenameUtils.getName("noseperator.inthispath"));
        assertEquals("c.txt", FilenameUtils.getName("a/b/c.txt"));
        assertEquals("c", FilenameUtils.getName("a/b/c"));
        assertEquals("", FilenameUtils.getName("a/b/c/"));
        assertEquals("c", FilenameUtils.getName("a\\b\\c"));
    }

    @Test
    void injectionFailure() {
        assertThrows(IllegalArgumentException.class, () -> FilenameUtils.getName("a\\b\\\u0000c"));
    }

    @Test
    void getBaseName() {
        assertNull(FilenameUtils.getBaseName(null));
        assertEquals("noseperator", FilenameUtils.getBaseName("noseperator.inthispath"));
        assertEquals("c", FilenameUtils.getBaseName("a/b/c.txt"));
        assertEquals("c", FilenameUtils.getBaseName("a/b/c"));
        assertEquals("", FilenameUtils.getBaseName("a/b/c/"));
        assertEquals("c", FilenameUtils.getBaseName("a\\b\\c"));
        assertEquals("file.txt", FilenameUtils.getBaseName("file.txt.bak"));
    }

    @Test
    void getBaseNameWithNullByte() {
        assertThrows(IllegalArgumentException.class, () -> FilenameUtils.getBaseName("fil\u0000e.txt.bak"));
    }

    @Test
    void getExtension() {
        assertNull(FilenameUtils.getExtension(null));
        assertEquals("ext", FilenameUtils.getExtension("file.ext"));
        assertEquals("", FilenameUtils.getExtension("README"));
        assertEquals("com", FilenameUtils.getExtension("domain.dot.com"));
        assertEquals("jpeg", FilenameUtils.getExtension("image.jpeg"));
        assertEquals("", FilenameUtils.getExtension("a.b/c"));
        assertEquals("txt", FilenameUtils.getExtension("a.b/c.txt"));
        assertEquals("", FilenameUtils.getExtension("a/b/c"));
        assertEquals("", FilenameUtils.getExtension("a.b\\c"));
        assertEquals("txt", FilenameUtils.getExtension("a.b\\c.txt"));
        assertEquals("", FilenameUtils.getExtension("a\\b\\c"));
        assertEquals("", FilenameUtils.getExtension("C:\\temp\\foo.bar\\README"));
        assertEquals("ext", FilenameUtils.getExtension("../filename.ext"));

        assertEquals("txt", FilenameUtils.getExtension("foo.exe:bar.txt"));
    }

    @Test
    void removeExtension() {
        assertNull(FilenameUtils.removeExtension(null));
        assertEquals("file", FilenameUtils.removeExtension("file.ext"));
        assertEquals("README", FilenameUtils.removeExtension("README"));
        assertEquals("domain.dot", FilenameUtils.removeExtension("domain.dot.com"));
        assertEquals("image", FilenameUtils.removeExtension("image.jpeg"));
        assertEquals("a.b/c", FilenameUtils.removeExtension("a.b/c"));
        assertEquals("a.b/c", FilenameUtils.removeExtension("a.b/c.txt"));
        assertEquals("a/b/c", FilenameUtils.removeExtension("a/b/c"));
        assertEquals("a.b\\c", FilenameUtils.removeExtension("a.b\\c"));
        assertEquals("a.b\\c", FilenameUtils.removeExtension("a.b\\c.txt"));
        assertEquals("a\\b\\c", FilenameUtils.removeExtension("a\\b\\c"));
        assertEquals("C:\\temp\\foo.bar\\README", FilenameUtils.removeExtension("C:\\temp\\foo.bar\\README"));
        assertEquals("../filename", FilenameUtils.removeExtension("../filename.ext"));
    }

    // -----------------------------------------------------------------------
    @Test
    void equals() {
        assertTrue(FilenameUtils.equals(null, null));
        assertFalse(FilenameUtils.equals(null, ""));
        assertFalse(FilenameUtils.equals("", null));
        assertTrue(FilenameUtils.equals("", ""));
        assertTrue(FilenameUtils.equals("file.txt", "file.txt"));
        assertFalse(FilenameUtils.equals("file.txt", "FILE.TXT"));
        assertFalse(FilenameUtils.equals("a\\b\\file.txt", "a/b/file.txt"));
    }

    @Test
    void equalsOnSystem() {
        assertTrue(FilenameUtils.equalsOnSystem(null, null));
        assertFalse(FilenameUtils.equalsOnSystem(null, ""));
        assertFalse(FilenameUtils.equalsOnSystem("", null));
        assertTrue(FilenameUtils.equalsOnSystem("", ""));
        assertTrue(FilenameUtils.equalsOnSystem("file.txt", "file.txt"));
        assertEquals(WINDOWS, FilenameUtils.equalsOnSystem("file.txt", "FILE.TXT"));
        assertFalse(FilenameUtils.equalsOnSystem("a\\b\\file.txt", "a/b/file.txt"));
    }

    // -----------------------------------------------------------------------
    @Test
    void equalsNormalized() {
        assertTrue(FilenameUtils.equalsNormalized(null, null));
        assertFalse(FilenameUtils.equalsNormalized(null, ""));
        assertFalse(FilenameUtils.equalsNormalized("", null));
        assertTrue(FilenameUtils.equalsNormalized("", ""));
        assertTrue(FilenameUtils.equalsNormalized("file.txt", "file.txt"));
        assertFalse(FilenameUtils.equalsNormalized("file.txt", "FILE.TXT"));
        assertTrue(FilenameUtils.equalsNormalized("a\\b\\file.txt", "a/b/file.txt"));
        assertFalse(FilenameUtils.equalsNormalized("a/b/", "a/b"));
    }

    @Test
    void equalsNormalizedOnSystem() {
        assertTrue(FilenameUtils.equalsNormalizedOnSystem(null, null));
        assertFalse(FilenameUtils.equalsNormalizedOnSystem(null, ""));
        assertFalse(FilenameUtils.equalsNormalizedOnSystem("", null));
        assertTrue(FilenameUtils.equalsNormalizedOnSystem("", ""));
        assertTrue(FilenameUtils.equalsNormalizedOnSystem("file.txt", "file.txt"));
        assertEquals(WINDOWS, FilenameUtils.equalsNormalizedOnSystem("file.txt", "FILE.TXT"));
        assertTrue(FilenameUtils.equalsNormalizedOnSystem("a\\b\\file.txt", "a/b/file.txt"));
        assertFalse(FilenameUtils.equalsNormalizedOnSystem("a/b/", "a/b"));
    }

    /**
     * Test for <a href="https://issues.apache.org/jira/browse/IO-128">...</a>
     */
    @Test
    void equalsNormalizedErrorIO128() {
        try {
            FilenameUtils.equalsNormalizedOnSystem("//file.txt", "file.txt");
            fail("Invalid normalized first file");
        } catch (final NullPointerException e) {
            // expected result
        }
        try {
            FilenameUtils.equalsNormalizedOnSystem("file.txt", "//file.txt");
            fail("Invalid normalized second file");
        } catch (final NullPointerException e) {
            // expected result
        }
        try {
            FilenameUtils.equalsNormalizedOnSystem("//file.txt", "//file.txt");
            fail("Invalid normalized both filse");
        } catch (final NullPointerException e) {
            // expected result
        }
    }

    @Test
    void equalsFullControl() {
        assertFalse(FilenameUtils.equals("file.txt", "FILE.TXT", true, IOCase.SENSITIVE));
        assertTrue(FilenameUtils.equals("file.txt", "FILE.TXT", true, IOCase.INSENSITIVE));
        assertEquals(WINDOWS, FilenameUtils.equals("file.txt", "FILE.TXT", true, IOCase.SYSTEM));
        assertFalse(FilenameUtils.equals("file.txt", "FILE.TXT", true, null));
    }

    // -----------------------------------------------------------------------
    @Test
    void isExtension() {
        assertFalse(FilenameUtils.isExtension(null, (String) null));
        assertFalse(FilenameUtils.isExtension("file.txt", (String) null));
        assertTrue(FilenameUtils.isExtension("file", (String) null));
        assertFalse(FilenameUtils.isExtension("file.txt", ""));
        assertTrue(FilenameUtils.isExtension("file", ""));
        assertTrue(FilenameUtils.isExtension("file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("file.txt", "rtf"));

        assertFalse(FilenameUtils.isExtension("a/b/file.txt", (String) null));
        assertFalse(FilenameUtils.isExtension("a/b/file.txt", ""));
        assertTrue(FilenameUtils.isExtension("a/b/file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("a/b/file.txt", "rtf"));

        assertFalse(FilenameUtils.isExtension("a.b/file.txt", (String) null));
        assertFalse(FilenameUtils.isExtension("a.b/file.txt", ""));
        assertTrue(FilenameUtils.isExtension("a.b/file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("a.b/file.txt", "rtf"));

        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt", (String) null));
        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt", ""));
        assertTrue(FilenameUtils.isExtension("a\\b\\file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt", "rtf"));

        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", (String) null));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", ""));
        assertTrue(FilenameUtils.isExtension("a.b\\file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", "rtf"));

        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", "TXT"));
    }

    @Test
    void isExtensionInjection() {
        assertThrows(IllegalArgumentException.class, () -> FilenameUtils.isExtension("a.b\\fi\u0000le.txt", "TXT"));
    }

    @Test
    void isExtensionArray() {
        assertFalse(FilenameUtils.isExtension(null, (String[]) null));
        assertFalse(FilenameUtils.isExtension("file.txt", (String[]) null));
        assertTrue(FilenameUtils.isExtension("file", (String[]) null));
        assertFalse(FilenameUtils.isExtension("file.txt"));
        assertTrue(FilenameUtils.isExtension("file.txt", new String[]{"txt"}));
        assertFalse(FilenameUtils.isExtension("file.txt", new String[]{"rtf"}));
        assertTrue(FilenameUtils.isExtension("file", "rtf", ""));
        assertTrue(FilenameUtils.isExtension("file.txt", "rtf", "txt"));

        assertFalse(FilenameUtils.isExtension("a/b/file.txt", (String[]) null));
        assertFalse(FilenameUtils.isExtension("a/b/file.txt"));
        assertTrue(FilenameUtils.isExtension("a/b/file.txt", new String[]{"txt"}));
        assertFalse(FilenameUtils.isExtension("a/b/file.txt", new String[]{"rtf"}));
        assertTrue(FilenameUtils.isExtension("a/b/file.txt", "rtf", "txt"));

        assertFalse(FilenameUtils.isExtension("a.b/file.txt", (String[]) null));
        assertFalse(FilenameUtils.isExtension("a.b/file.txt"));
        assertTrue(FilenameUtils.isExtension("a.b/file.txt", new String[]{"txt"}));
        assertFalse(FilenameUtils.isExtension("a.b/file.txt", new String[]{"rtf"}));
        assertTrue(FilenameUtils.isExtension("a.b/file.txt", "rtf", "txt"));

        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt", (String[]) null));
        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt"));
        assertTrue(FilenameUtils.isExtension("a\\b\\file.txt", new String[]{"txt"}));
        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt", new String[]{"rtf"}));
        assertTrue(FilenameUtils.isExtension("a\\b\\file.txt", "rtf", "txt"));

        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", (String[]) null));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt"));
        assertTrue(FilenameUtils.isExtension("a.b\\file.txt", new String[]{"txt"}));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", new String[]{"rtf"}));
        assertTrue(FilenameUtils.isExtension("a.b\\file.txt", "rtf", "txt"));

        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", new String[]{"TXT"}));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", "TXT", "RTF"));
    }

    @Test
    void isExtensionVarArgs() {
        assertTrue(FilenameUtils.isExtension("file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("file.txt", "rtf"));
        assertTrue(FilenameUtils.isExtension("file", "rtf", ""));
        assertTrue(FilenameUtils.isExtension("file.txt", "rtf", "txt"));

        assertTrue(FilenameUtils.isExtension("a/b/file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("a/b/file.txt", "rtf"));
        assertTrue(FilenameUtils.isExtension("a/b/file.txt", "rtf", "txt"));

        assertTrue(FilenameUtils.isExtension("a.b/file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("a.b/file.txt", "rtf"));
        assertTrue(FilenameUtils.isExtension("a.b/file.txt", "rtf", "txt"));

        assertTrue(FilenameUtils.isExtension("a\\b\\file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt", "rtf"));
        assertTrue(FilenameUtils.isExtension("a\\b\\file.txt", "rtf", "txt"));

        assertTrue(FilenameUtils.isExtension("a.b\\file.txt", "txt"));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", "rtf"));
        assertTrue(FilenameUtils.isExtension("a.b\\file.txt", "rtf", "txt"));

        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", "TXT"));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", "TXT", "RTF"));
    }

    @Test
    void isExtensionCollection() {
        assertFalse(FilenameUtils.isExtension(null, (Collection<String>) null));
        assertFalse(FilenameUtils.isExtension("file.txt", (Collection<String>) null));
        assertTrue(FilenameUtils.isExtension("file", (Collection<String>) null));
        assertFalse(FilenameUtils.isExtension("file.txt", new ArrayList<>()));
        assertTrue(FilenameUtils.isExtension("file.txt", new ArrayList<>(List.of("txt"))));
        assertFalse(FilenameUtils.isExtension("file.txt", new ArrayList<>(List.of("rtf"))));
        assertTrue(FilenameUtils.isExtension("file", new ArrayList<>(Arrays.asList("rtf", ""))));
        assertTrue(FilenameUtils.isExtension("file.txt", new ArrayList<>(Arrays.asList("rtf", "txt"))));

        assertFalse(FilenameUtils.isExtension("a/b/file.txt", (Collection<String>) null));
        assertFalse(FilenameUtils.isExtension("a/b/file.txt", new ArrayList<>()));
        assertTrue(FilenameUtils.isExtension("a/b/file.txt", new ArrayList<>(List.of("txt"))));
        assertFalse(FilenameUtils.isExtension("a/b/file.txt", new ArrayList<>(List.of("rtf"))));
        assertTrue(FilenameUtils.isExtension("a/b/file.txt", new ArrayList<>(Arrays.asList("rtf", "txt"))));

        assertFalse(FilenameUtils.isExtension("a.b/file.txt", (Collection<String>) null));
        assertFalse(FilenameUtils.isExtension("a.b/file.txt", new ArrayList<>()));
        assertTrue(FilenameUtils.isExtension("a.b/file.txt", new ArrayList<>(List.of("txt"))));
        assertFalse(FilenameUtils.isExtension("a.b/file.txt", new ArrayList<>(List.of("rtf"))));
        assertTrue(FilenameUtils.isExtension("a.b/file.txt", new ArrayList<>(Arrays.asList("rtf", "txt"))));

        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt", (Collection<String>) null));
        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt", new ArrayList<>()));
        assertTrue(FilenameUtils.isExtension("a\\b\\file.txt", new ArrayList<>(List.of("txt"))));
        assertFalse(FilenameUtils.isExtension("a\\b\\file.txt", new ArrayList<>(List.of("rtf"))));
        assertTrue(FilenameUtils.isExtension("a\\b\\file.txt", new ArrayList<>(Arrays.asList("rtf", "txt"))));

        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", (Collection<String>) null));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", new ArrayList<>()));
        assertTrue(FilenameUtils.isExtension("a.b\\file.txt", new ArrayList<>(List.of("txt"))));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", new ArrayList<>(List.of("rtf"))));
        assertTrue(FilenameUtils.isExtension("a.b\\file.txt", new ArrayList<>(Arrays.asList("rtf", "txt"))));

        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", new ArrayList<>(List.of("TXT"))));
        assertFalse(FilenameUtils.isExtension("a.b\\file.txt", new ArrayList<>(Arrays.asList("TXT", "RTF"))));
    }

    @Test
    void directoryContains() {
        // Test null parent - should throw IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () -> FilenameUtils.directoryContains(null, "/child"));
        assertThrows(IllegalArgumentException.class, () -> FilenameUtils.directoryContains(null, null));

        // Test null child - should return false
        assertFalse(FilenameUtils.directoryContains("/parent", null));

        // Test same paths - should return false (directory does not contain itself)
        assertFalse(FilenameUtils.directoryContains("/parent", "/parent"));
        assertFalse(FilenameUtils.directoryContains("/parent/", "/parent/"));
        assertFalse(FilenameUtils.directoryContains("/parent", "/parent/"));
        assertFalse(FilenameUtils.directoryContains("/parent/", "/parent"));

        // Test normal containment cases - Unix style paths
        assertTrue(FilenameUtils.directoryContains("/parent", "/parent/child"));
        assertTrue(FilenameUtils.directoryContains("/parent", "/parent/child/grandchild"));
        assertTrue(FilenameUtils.directoryContains("/parent/", "/parent/child"));
        assertTrue(FilenameUtils.directoryContains("/parent", "/parent/child/"));
        assertTrue(FilenameUtils.directoryContains("/parent/", "/parent/child/"));

        // Test normal containment cases - Windows style paths
        assertTrue(FilenameUtils.directoryContains("C:\\parent", "C:\\parent\\child"));
        assertTrue(FilenameUtils.directoryContains("C:\\parent", "C:\\parent\\child\\grandchild"));
        assertTrue(FilenameUtils.directoryContains("C:\\parent\\", "C:\\parent\\child"));
        assertTrue(FilenameUtils.directoryContains("C:\\parent", "C:\\parent\\child\\"));
        assertTrue(FilenameUtils.directoryContains("C:\\parent\\", "C:\\parent\\child\\"));

        // Test non-containment cases
        assertFalse(FilenameUtils.directoryContains("/parent", "/other"));
        assertFalse(FilenameUtils.directoryContains("/parent", "/parent2"));
        assertFalse(FilenameUtils.directoryContains("/parent", "/parentchild"));
        assertFalse(FilenameUtils.directoryContains("/parent/child", "/parent"));
        assertFalse(FilenameUtils.directoryContains("/parent/child", "/parent/sibling"));

        // Test mixed separators
        assertTrue(FilenameUtils.directoryContains("/parent", "/parent\\child"));
        assertTrue(FilenameUtils.directoryContains("C:\\parent", "C:\\parent/child"));

        // Test relative paths
        assertTrue(FilenameUtils.directoryContains("parent", "parent/child"));
        assertTrue(FilenameUtils.directoryContains("parent", "parent\\child"));
        assertFalse(FilenameUtils.directoryContains("parent", "parent"));
        assertFalse(FilenameUtils.directoryContains("parent", "other"));

        // Test empty strings
        assertFalse(FilenameUtils.directoryContains("", "child"));
        assertFalse(FilenameUtils.directoryContains("parent", ""));
        assertFalse(FilenameUtils.directoryContains("", ""));

        // Test root directory cases
        assertTrue(FilenameUtils.directoryContains("/", "/child"));
        assertTrue(FilenameUtils.directoryContains("C:\\", "C:\\child"));
        assertFalse(FilenameUtils.directoryContains("/", "/"));
        assertFalse(FilenameUtils.directoryContains("C:\\", "C:\\"));

        // Test complex paths
        assertTrue(FilenameUtils.directoryContains("/home/user", "/home/user/documents"));
        assertTrue(FilenameUtils.directoryContains("/home/user", "/home/user/documents/file.txt"));
        assertFalse(FilenameUtils.directoryContains("/home/user", "/home/other"));
        assertFalse(FilenameUtils.directoryContains("/home/user", "/home/username"));

        // Test UNC paths (Windows network paths)
        assertTrue(FilenameUtils.directoryContains("\\\\server\\share", "\\\\server\\share\\folder"));
        assertFalse(FilenameUtils.directoryContains("\\\\server\\share", "\\\\server\\share"));
        assertFalse(FilenameUtils.directoryContains("\\\\server\\share", "\\\\other\\share\\folder"));
    }
}
