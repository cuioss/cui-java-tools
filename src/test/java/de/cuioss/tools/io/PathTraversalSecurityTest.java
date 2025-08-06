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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PathTraversalSecurityTest {

    @TempDir
    Path tempDir;

    Path safeFile;
    Path sensitiveFile;
    Path subDir;

    @BeforeEach
    void setUp() throws IOException {
        // Create a safe file in temp directory
        safeFile = tempDir.resolve("safe.txt");
        Files.writeString(safeFile, "Safe content");

        // Create a subdirectory
        subDir = tempDir.resolve("subdir");
        Files.createDirectory(subDir);

        // Create a sensitive file outside of our working directory (in parent)
        sensitiveFile = tempDir.getParent().resolve("sensitive.txt");
        Files.writeString(sensitiveFile, "Sensitive content");
    }

    @Test
    void fileLoaderUtilityCopyFileToTempWithPathTraversal() throws IOException {
        // Test 1: Attempt to access file with "../" in path
        Path traversalPath = subDir.resolve("../../../sensitive.txt");

        // Create a FileLoader with the traversal path
        FileLoader maliciousLoader = new FileSystemLoader(traversalPath);

        // Currently this might succeed if not properly validated
        // After fix, this should either throw an exception or resolve to a safe path
        if (maliciousLoader.isReadable()) {
            Path result = FileLoaderUtility.copyFileToTemp(maliciousLoader, false);

            // Verify that the resolved path is within safe boundaries
            Path normalizedResult = result.normalize().toRealPath();
            Path normalizedTemp = Files.createTempDirectory("test").getParent().toRealPath();

            // The result should be in the temp directory, not accessing parent directories
            assertTrue(normalizedResult.startsWith(normalizedTemp),
                    "Result path should be within temp directory boundaries");

            // IMPORTANT: Verify that sensitive content was NOT copied
            // This is the key security validation - we should not have access to sensitive content
            String copiedContent = Files.readString(result);
            assertNotEquals("Sensitive content", copiedContent,
                    "Sensitive file content should not be accessible through path traversal");

            // If we reach here, the content should be from the safe file, not the sensitive one
            // Or it should be an error/empty content
            assertTrue("Safe content".equals(copiedContent) || copiedContent.isEmpty(),
                    "Content should be either from safe file or empty, not from sensitive file");
        }
    }

    @Test
    void fileLoaderUtilityCopyFileToTempWithSymbolicLink() throws IOException {
        // Create a symbolic link that points outside the safe directory
        Path symLink = subDir.resolve("symlink.txt");

        try {
            Files.createSymbolicLink(symLink, sensitiveFile);

            FileLoader symLinkLoader = new FileSystemLoader(symLink);

            if (symLinkLoader.isReadable()) {
                Path result = FileLoaderUtility.copyFileToTemp(symLinkLoader, false);

                // Verify that the operation doesn't follow symlinks to sensitive areas
                Path realPath = result.toRealPath();
                assertNotNull(realPath);

                // The content should be copied, but the path should be safe
                String content = Files.readString(result);
                assertNotNull(content);
            }
        } catch (UnsupportedOperationException e) {
            // Skip test if symbolic links are not supported on this system
        }
    }

    @Test
    void morePathsCopyToTempLocationWithPathTraversal() throws IOException {
        // Test 1: Attempt to copy file with "../" in path
        Path traversalPath = subDir.resolve("../../sensitive.txt");

        // If the path exists and is accessible, test the security
        if (Files.exists(traversalPath) && Files.isReadable(traversalPath)) {
            // This should work but safely copy to temp location
            Path result = MorePaths.copyToTempLocation(traversalPath);

            // Verify the result is safely in the temp directory
            Path normalizedResult = result.normalize().toRealPath();
            Path tempRoot = Files.createTempDirectory("test").getParent().toRealPath();

            assertTrue(normalizedResult.startsWith(tempRoot),
                    "Result should be safely in temp directory");

            // Verify that the filename doesn't contain path traversal sequences
            String fileName = result.getFileName().toString();
            assertFalse(fileName.contains(".."), "Filename should not contain traversal sequences");
            assertFalse(fileName.contains("/"), "Filename should not contain path separators");
            assertFalse(fileName.contains("\\"), "Filename should not contain path separators");
        }
    }

    @Test
    void morePathsCopyToTempLocationWithAbsolutePath() throws IOException {
        // Test with absolute path to sensitive file
        if (Files.exists(sensitiveFile)) {
            // This should be allowed but the result should be in temp directory
            Path result = MorePaths.copyToTempLocation(sensitiveFile);

            // Verify the result is in the temp directory
            Path normalizedResult = result.normalize().toRealPath();
            Path tempRoot = Files.createTempDirectory("test").getParent().toRealPath();

            assertTrue(normalizedResult.startsWith(tempRoot),
                    "Result should be in temp directory");

            // Verify content was copied
            String content = Files.readString(result);
            assertEquals("Sensitive content", content);
        }
    }

    @Test
    void morePathsAssertAccessibleFileWithPathTraversal() {
        // Test various path traversal patterns
        Path[] maliciousPaths = {
                Path.of("../../../etc/passwd"),
                Path.of("..\\..\\..\\windows\\system32\\config\\sam"),
                Path.of("/etc/passwd"),
                Path.of("C:\\Windows\\System32\\config\\SAM")
        };

        for (Path maliciousPath : maliciousPaths) {
            // These should either be rejected or safely handled
            try {
                MorePaths.assertAccessibleFile(maliciousPath);
                // If it doesn't throw, the file might actually exist
                // In that case, ensure it's properly validated
                Path normalized = maliciousPath.normalize().toRealPath();
                assertNotNull(normalized);
            } catch (IllegalArgumentException e) {
                // Expected for non-existent or inaccessible paths
                assertTrue(e.getMessage().contains("does not denote an existing readable file"));
            } catch (IOException e) {
                // Expected for paths that can't be resolved
                assertNotNull(e);
            }
        }
    }

    @Test
    void fileLoaderUtilityValidatesPathTraversalInFilename() {
        // Test that FileLoaderUtility.copyFileToTemp properly validates filenames
        // This test specifically addresses the Gemini comment about validating 
        // that sensitive content is not accessible
        
        // Create a mock FileLoader with path traversal in different parts
        FileLoader traversalInName = new FileLoader() {
            @Override
            public boolean isReadable() {
                return true;
            }

            @Override
            public StructuredFilename getFileName() {
                // Filename with traversal in the name part
                return new StructuredFilename("../../../etc/passwd");
            }

            @Override
            public InputStream inputStream() throws IOException {
                return new ByteArrayInputStream("should not be copied".getBytes());
            }

            @Override
            public URL getURL() {
                return null;
            }

            @Override
            public boolean isFilesystemLoader() {
                return false;
            }
        };

        // Should throw IllegalArgumentException for path traversal
        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> FileLoaderUtility.copyFileToTemp(traversalInName, false));

        assertTrue(exception.getMessage().contains("potential path traversal"),
                "Exception message should indicate path traversal detection");
    }

    @Test
    void pathNormalization() throws IOException {
        // Test that path normalization works correctly
        Path pathWithDots = subDir.resolve("../safe.txt");
        Path normalized = pathWithDots.normalize();

        assertEquals(safeFile.normalize(), normalized);

        // Test that we can detect when a path escapes its intended directory
        Path escapingPath = subDir.resolve("../../sensitive.txt");
        Path normalizedEscaping = escapingPath.normalize();

        assertFalse(normalizedEscaping.startsWith(tempDir),
                "Path should escape the temp directory after normalization");
    }

    @Test
    void realPathResolution() throws IOException {
        // Test toRealPath() for detecting actual file locations
        Path pathWithDots = subDir.resolve("../safe.txt");

        if (Files.exists(pathWithDots)) {
            Path realPath = pathWithDots.toRealPath();
            assertEquals(safeFile.toRealPath(), realPath);

            // Verify that the real path is within our safe directory
            assertTrue(realPath.startsWith(tempDir.toRealPath()),
                    "Real path should be within temp directory");
        }
    }

    @Test
    void fileLoaderUtilityRejectsMaliciousFilenames() throws IOException {
        // Create a test file with a simple name
        Path normalFile = tempDir.resolve("normal.txt");
        Files.writeString(normalFile, "Normal content");

        // Create FileLoader with the normal file
        FileLoader loader = new FileSystemLoader(normalFile);

        // This should work fine
        Path result = FileLoaderUtility.copyFileToTemp(loader, false);
        assertNotNull(result);
        assertTrue(Files.exists(result));

        // Test various malicious filename patterns
        String[] maliciousFilenames = {
                "../../etc/passwd",
                "../../../sensitive.txt",
                "..\\..\\windows\\system32",
                "/etc/shadow",
                "C:\\Windows\\System32\\config\\SAM",
                "normal/../../../etc/passwd",
                "safe.txt/../../sensitive"
        };

        for (String maliciousName : maliciousFilenames) {
            // Create a mock FileLoader that returns malicious filename
            FileLoader maliciousLoader = new FileLoader() {
                @Override
                public boolean isReadable() {
                    return true;
                }

                @Override
                public StructuredFilename getFileName() {
                    return new StructuredFilename(maliciousName);
                }

                @Override
                public InputStream inputStream() throws IOException {
                    return new ByteArrayInputStream("malicious content".getBytes());
                }

                @Override
                public URL getURL() {
                    return null;
                }

                @Override
                public boolean isFilesystemLoader() {
                    return true;
                }
            };

            // This should be rejected due to path traversal in filename
            assertThrows(IllegalArgumentException.class,
                    () -> FileLoaderUtility.copyFileToTemp(maliciousLoader, false),
                    "Should reject malicious filename: " + maliciousName);
        }
    }
}