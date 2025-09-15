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
 * Generator for valid URL paths.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 *
 * Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining realistic URL path patterns.
 *
 * Provides common valid URL path examples for testing.
 */
public class ValidURLPathGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> pathTypeGen = Generators.integers(1, 7);
    private final TypedGenerator<Integer> apiVersionGen = Generators.integers(1, 3);
    private final TypedGenerator<Integer> resourceGen = Generators.integers(1, 5);
    private final TypedGenerator<Integer> actionGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> adminActionGen = Generators.integers(1, 3);
    private final TypedGenerator<Integer> systemPathGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> nestedResourceGen = Generators.integers(1, 4);
    private final TypedGenerator<Boolean> includeIdGen = Generators.booleans();

    @Override
    public String next() {
        return switch (pathTypeGen.next()) {
            case 1 -> generateApiPath();
            case 2 -> generateVersionedApiPath();
            case 3 -> generateNestedResourcePath();
            case 4 -> generateSystemPath();
            case 5 -> generateAuthPath();
            case 6 -> generateAdminPath();
            case 7 -> generateReportingPath();
            default -> generateApiPath();
        };
    }

    private String generateApiPath() {
        String resource = generateResource();
        if (includeIdGen.next()) {
            String action = generateAction();
            return "/api/" + resource + "/" + generateId() + "/" + action;
        }
        return "/api/" + resource;
    }

    private String generateVersionedApiPath() {
        String version = generateApiVersion();
        String resource = generateResource();
        if (includeIdGen.next()) {
            return "/api/" + version + "/" + resource + "/" + generateId();
        }
        return "/api/" + version + "/" + resource;
    }

    private String generateNestedResourcePath() {
        String parentResource = generateResource();
        String childResource = generateNestedResource();
        return "/api/" + parentResource + "/" + generateId() + "/" + childResource;
    }

    private String generateSystemPath() {
        return switch (systemPathGen.next()) {
            case 1 -> "/health";
            case 2 -> "/metrics";
            case 3 -> "/status";
            case 4 -> "/info";
            default -> "/health";
        };
    }

    private String generateAuthPath() {
        String action = generateAction();
        return "/api/auth/" + action;
    }

    private String generateAdminPath() {
        String action = generateAdminAction();
        return "/api/admin/" + action;
    }

    private String generateReportingPath() {
        String reportType = switch (Generators.integers(1, 3).next()) {
            case 1 -> "daily";
            case 2 -> "summary";
            case 3 -> "status";
            default -> "daily";
        };
        return "/api/" + generateReportCategory() + "/" + reportType;
    }

    private String generateApiVersion() {
        return switch (apiVersionGen.next()) {
            case 1 -> "v1";
            case 2 -> "v2";
            case 3 -> "v3";
            default -> "v1";
        };
    }

    private String generateResource() {
        return switch (resourceGen.next()) {
            case 1 -> "users";
            case 2 -> "orders";
            case 3 -> "products";
            case 4 -> "customers";
            case 5 -> "documents";
            default -> "users";
        };
    }

    private String generateAction() {
        return switch (actionGen.next()) {
            case 1 -> "search";
            case 2 -> "profile";
            case 3 -> "login";
            case 4 -> "logout";
            default -> "search";
        };
    }

    private String generateAdminAction() {
        return switch (adminActionGen.next()) {
            case 1 -> "dashboard";
            case 2 -> "settings";
            case 3 -> "config";
            default -> "dashboard";
        };
    }

    private String generateNestedResource() {
        return switch (nestedResourceGen.next()) {
            case 1 -> "items";
            case 2 -> "orders";
            case 3 -> "profile";
            case 4 -> "notifications";
            default -> "items";
        };
    }

    private String generateReportCategory() {
        return switch (Generators.integers(1, 3).next()) {
            case 1 -> "reports";
            case 2 -> "stats";
            case 3 -> "backup";
            default -> "reports";
        };
    }

    private String generateId() {
        return switch (Generators.integers(1, 3).next()) {
            case 1 -> "123";
            case 2 -> "456";
            case 3 -> Generators.integers(100, 999).next().toString();
            default -> "123";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}