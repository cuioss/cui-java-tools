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
package de.cuioss.http.security.generators.encoding;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for path traversal attack patterns.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 *
 * This generator creates various path traversal patterns including:
 * - Basic traversal sequences (../, ..\\)
 * - Encoded variants (%2e%2e%2f, %252e%252e%252f)
 * - Unicode variants (\\u002e\\u002e\\u002f)
 * - Mixed encoding attempts
 * - Null byte injection variants
 *
 * IMPROVED: Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining attack effectiveness.
 *
 * Based on CVE analysis and OWASP attack patterns from specification.
 *
 * @author Claude Code Generator
 */
public class PathTraversalGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> depthGenerator = Generators.integers(1, 8);
    private final TypedGenerator<Integer> pathTypeGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> attackTypeGenerator = Generators.integers(0, 6);
    private final TypedGenerator<Integer> systemTypeGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> extensionTypeGen = Generators.integers(1, 4);
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();

    @Override
    public String next() {
        int attackType = attackTypeGenerator.next();

        String pattern = switch (attackType) {
            case 0 -> generateBasicTraversal();
            case 1 -> generateEncodedTraversal();
            case 2 -> generateDoubleEncodedTraversal();
            case 3 -> generateUnicodeTraversal();
            case 4 -> generateMixedEncodingTraversal();
            case 5 -> generateNullByteTraversal();
            case 6 -> generateAdvancedTraversal();
            default -> generateBasicTraversal();
        };

        // Occasionally add random context to make patterns more realistic
        if (contextSelector.next()) {
            return addRandomContext(pattern);
        }

        return pattern;
    }

    private String generateBasicTraversal() {
        int depth = depthGenerator.next();
        String separator = generateSeparator();
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            pattern.append("..").append(separator);
        }

        // Sometimes add target file
        if (contextSelector.next()) {
            pattern.append(generateTargetFile());
        }

        return pattern.toString();
    }

    private String generateSeparator() {
        int sepType = Generators.integers(0, 1).next();
        return switch (sepType) {
            case 0 -> "/";
            case 1 -> "\\";
            default -> "/";
        };
    }

    private String generateTargetFile() {
        int fileType = Generators.integers(0, 6).next();
        return switch (fileType) {
            case 0 -> "etc/passwd";
            case 1 -> "windows/win.ini";
            case 2 -> "boot.ini";
            case 3 -> "etc/shadow";
            case 4 -> "etc/hosts";
            case 5 -> "windows/system32/config/sam";
            case 6 -> "proc/self/environ";
            default -> "etc/passwd";
        };
    }

    private String generateFileExtension() {
        int extType = Generators.integers(0, 7).next();
        return switch (extType) {
            case 0 -> "jpg";
            case 1 -> "exe";
            case 2 -> "png";
            case 3 -> "gif";
            case 4 -> "txt";
            case 5 -> "php";
            case 6 -> "jsp";
            case 7 -> "asp";
            default -> "txt";
        };
    }

    private String generatePrefix() {
        int prefixType = Generators.integers(0, 6).next();
        return switch (prefixType) {
            case 0 -> "/api/users/";
            case 1 -> "/admin/";
            case 2 -> "/files/";
            case 3 -> "/uploads/";
            case 4 -> "/documents/";
            case 5 -> "/images/";
            case 6 -> "";
            default -> "/api/users/";
        };
    }

    private String generateSuffix() {
        int suffixType = Generators.integers(0, 5).next();
        return switch (suffixType) {
            case 0 -> "/sensitive.txt";
            case 1 -> "/config.xml";
            case 2 -> ".php";
            case 3 -> ".jsp";
            case 4 -> ".asp";
            case 5 -> "";
            default -> "/sensitive.txt";
        };
    }

    private String generateEncodedTraversal() {
        int depth = depthGenerator.next();
        boolean useBackslash = "\\".equals(generateSeparator());
        StringBuilder pattern = new StringBuilder();

        String dotEncoded = "%2e";
        String separatorEncoded = useBackslash ? "%5c" : "%2f";

        for (int i = 0; i < depth; i++) {
            pattern.append(dotEncoded).append(dotEncoded).append(separatorEncoded);
        }

        if (contextSelector.next()) {
            String target = generateTargetFile().replace("/", separatorEncoded).replace("\\", "%5c");
            pattern.append(target);
        }

        return pattern.toString();
    }

    private String generateDoubleEncodedTraversal() {
        int depth = depthGenerator.next();
        boolean useBackslash = "\\".equals(generateSeparator());
        StringBuilder pattern = new StringBuilder();

        String dotEncoded = "%252e";
        String separatorEncoded = useBackslash ? "%255c" : "%252f";

        for (int i = 0; i < depth; i++) {
            pattern.append(dotEncoded).append(dotEncoded).append(separatorEncoded);
        }

        return pattern.toString();
    }

    private String generateUnicodeTraversal() {
        int depth = depthGenerator.next();
        boolean useBackslash = "\\".equals(generateSeparator());
        StringBuilder pattern = new StringBuilder();

        String dotUnicode = "\\u002e";
        String separatorUnicode = useBackslash ? "\\u005c" : "\\u002f";

        for (int i = 0; i < depth; i++) {
            pattern.append(dotUnicode).append(dotUnicode).append(separatorUnicode);
        }

        return pattern.toString();
    }

    private String generateMixedEncodingTraversal() {
        int depth = depthGenerator.next();
        String separator = generateSeparator();
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            // Mix different encoding types randomly
            int encodingChoice = Generators.integers(0, 3).next();
            switch (encodingChoice) {
                case 0 -> pattern.append("..").append(separator);
                case 1 -> pattern.append("%2e%2e").append(separator);
                case 2 -> pattern.append("\\u002e\\u002e").append(separator);
                case 3 -> pattern.append("%2e%2e").append("/".equals(separator) ? "%2f" : "%5c");
            }
        }

        return pattern.toString();
    }

    private String generateNullByteTraversal() {
        String basePattern = generateBasicTraversal();

        // Add null byte in various positions
        int nullBytePosition = Generators.integers(0, 3).next();
        return switch (nullBytePosition) {
            case 0 -> basePattern + "%00";
            case 1 -> basePattern + "%00." + generateFileExtension();
            case 2 -> basePattern.replace("..", "..%00");
            case 3 -> basePattern + generateTargetFile() + "%00." + generateFileExtension();
            default -> basePattern + "%00";
        };
    }

    private String generateAdvancedTraversal() {
        int depth = depthGenerator.next();
        String separator = generateSeparator();
        StringBuilder pattern = new StringBuilder();

        // Generate corrupted/advanced patterns
        int advancedType = Generators.integers(0, 4).next();
        switch (advancedType) {
            case 0 -> {
                // Double dots with extra dots
                for (int i = 0; i < depth; i++) {
                    pattern.append("....").append(separator).append(separator);
                }
            }
            case 1 -> {
                // Mixed separators
                for (int i = 0; i < depth; i++) {
                    pattern.append("..").append("/").append("..").append("\\");
                }
            }
            case 2 -> {
                // Overlong encoding attempts
                for (int i = 0; i < depth; i++) {
                    pattern.append("%c0%ae%c0%ae%c0%af");
                }
            }
            case 3 -> {
                // Path with full system paths
                pattern.append(contextSelector.next() ? "/var/www/" : "C:\\inetpub\\wwwroot\\");
                pattern.append(generateBasicTraversal());
            }
            case 4 -> {
                // Unicode overlong sequences
                for (int i = 0; i < depth; i++) {
                    pattern.append("\\ufe0e\\ufe0e\\u2044");
                }
            }
        }

        return pattern.toString();
    }

    private String addRandomContext(String basePattern) {
        String prefix = generatePrefix();
        String suffix = generateSuffix();
        return prefix + basePattern + suffix;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}