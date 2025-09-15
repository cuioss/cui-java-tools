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
package de.cuioss.http.security.generators.url;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for URL paths containing path traversal attacks.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 *
 * Provides various encoded path traversal patterns in URL context.
 */
public class PathTraversalURLGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> encodingTypeGen = Generators.integers(1, 6);
    private final TypedGenerator<Integer> depthGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> apiPathSelector = Generators.integers(1, 10);
    private final TypedGenerator<Integer> targetSelector = Generators.integers(1, 10);
    private final TypedGenerator<Boolean> mixedEncodingGen = Generators.booleans();

    @Override
    public String next() {
        return switch (encodingTypeGen.next()) {
            case 1 -> generateBasicEncodedTraversal();
            case 2 -> generateWindowsStyleTraversal();
            case 3 -> generateDoubleEncodedTraversal();
            case 4 -> generateMixedEncodingTraversal();
            case 5 -> generateLowercaseEncodedTraversal();
            case 6 -> generateMultipleDepthTraversal();
            default -> generateBasicEncodedTraversal();
        };
    }

    private String generateBasicEncodedTraversal() {
        String apiPath = generateApiPath();
        String target = generateTarget();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");
        for (int i = 0; i < depth; i++) {
            pattern.append("%2E%2E/");
        }
        pattern.append(target);

        return pattern.toString();
    }

    private String generateWindowsStyleTraversal() {
        String apiPath = generateApiPath();
        String target = generateTarget();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");
        for (int i = 0; i < depth; i++) {
            pattern.append("%2E%2E%5C");
        }
        pattern.append(target);

        return pattern.toString();
    }

    private String generateDoubleEncodedTraversal() {
        String apiPath = generateApiPath();
        String target = generateTarget();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");
        for (int i = 0; i < depth; i++) {
            pattern.append("%252e%252e%252f");
        }
        pattern.append(target);

        return pattern.toString();
    }

    private String generateMixedEncodingTraversal() {
        String apiPath = generateApiPath();
        String target = generateTarget();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");

        // Mix encoded and unencoded traversal
        for (int i = 0; i < depth; i++) {
            if (mixedEncodingGen.next()) {
                pattern.append("%2E%2E/");
            } else {
                pattern.append("../");
            }
        }

        // Sometimes add encoded target path
        if (mixedEncodingGen.next()) {
            pattern.append(target.replace("/", "%2f"));
        } else {
            pattern.append(target);
        }

        return pattern.toString();
    }

    private String generateLowercaseEncodedTraversal() {
        String apiPath = generateApiPath();
        String target = generateTarget();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");
        for (int i = 0; i < depth; i++) {
            pattern.append("%2e%2e/");
        }
        pattern.append(target);

        return pattern.toString();
    }

    private String generateMultipleDepthTraversal() {
        String apiPath = generateApiPath();
        String target = generateTarget();

        // Generate deep traversal pattern
        StringBuilder pattern = new StringBuilder("/" + apiPath + "/users/");

        // Add 3+ levels of traversal
        int deepDepth = Generators.integers(3, 6).next();
        for (int i = 0; i < deepDepth; i++) {
            pattern.append("%2E%2E%2F");
        }
        pattern.append(target);

        return pattern.toString();
    }

    // QI-6: Dynamic API path generation
    private String generateApiPath() {
        return switch (apiPathSelector.next()) {
            case 1 -> "api";
            case 2 -> "files";
            case 3 -> "admin";
            case 4 -> "users";
            case 5 -> "docs";
            case 6 -> "backup";
            case 7 -> "upload";
            case 8 -> "download";
            case 9 -> "data";
            case 10 -> "content";
            default -> "api";
        };
    }

    // QI-6: Dynamic target generation
    private String generateTarget() {
        return switch (targetSelector.next()) {
            case 1 -> "admin";
            case 2 -> "etc/passwd";
            case 3 -> "config";
            case 4 -> "windows";
            case 5 -> "etc/shadow";
            case 6 -> "etc/hosts";
            case 7 -> "var/log";
            case 8 -> "system32";
            case 9 -> "root";
            case 10 -> "root/.ssh";
            default -> "etc/passwd";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}