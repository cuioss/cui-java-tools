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
package de.cuioss.http.security.database;

import java.util.List;

/**
 * Database of legitimate path patterns that must be accepted by the validation system.
 *
 * <p><strong>FALSE POSITIVE PREVENTION - T31:</strong> This database contains legitimate
 * path patterns that represent valid business use cases. These patterns ensure the security
 * validation doesn't incorrectly reject valid application paths that might appear suspicious
 * but are actually safe and necessary.</p>
 *
 * <h3>Coverage Areas</h3>
 * <ul>
 *   <li><strong>RESTful API Paths</strong> - Standard REST endpoint patterns</li>
 *   <li><strong>Resource Paths</strong> - Static resource and asset paths</li>
 *   <li><strong>Framework Patterns</strong> - Common web framework URL patterns</li>
 *   <li><strong>Version Paths</strong> - API versioning patterns</li>
 *   <li><strong>Deep Nesting</strong> - Legitimately deep path hierarchies</li>
 * </ul>
 *
 * @since 2.5
 */
public class LegitimatePathPatternsDatabase implements LegitimatePatternDatabase {

    // RESTful API Patterns
    public static final LegitimateTestCase REST_API_VERSION = new LegitimateTestCase(
            "/api/v1/users",
            "Standard RESTful API versioning pattern used by most modern APIs",
            "API versioning with /api/v1/, /api/v2/ is a standard practice that must be accepted"
    );

    public static final LegitimateTestCase REST_RESOURCE_ID = new LegitimateTestCase(
            "/api/users/12345/profile",
            "RESTful resource with numeric ID accessing sub-resource",
            "Numeric IDs in paths are standard for REST APIs and must be accepted"
    );

    public static final LegitimateTestCase REST_UUID_RESOURCE = new LegitimateTestCase(
            "/api/documents/550e8400-e29b-41d4-a716-446655440000",
            "RESTful resource identified by UUID",
            "UUIDs are commonly used as resource identifiers and contain hyphens which must be accepted"
    );

    public static final LegitimateTestCase REST_NESTED_RESOURCES = new LegitimateTestCase(
            "/api/organizations/123/departments/456/employees/789",
            "Deeply nested RESTful resources representing hierarchical data",
            "Hierarchical REST resources require deep nesting that must be accepted"
    );

    // Static Resource Patterns
    public static final LegitimateTestCase STATIC_VERSIONED_ASSET = new LegitimateTestCase(
            "/assets/css/main.v2.1.3.min.css",
            "Versioned and minified CSS asset with multiple dots",
            "Asset versioning often uses multiple dots for version numbers which must be accepted"
    );

    public static final LegitimateTestCase STATIC_HASH_ASSET = new LegitimateTestCase(
            "/dist/bundle.7d3f5e8a9b2c.js",
            "Webpack/build tool generated bundle with content hash",
            "Build tools generate hashes in filenames for cache busting which must be accepted"
    );

    public static final LegitimateTestCase STATIC_NESTED_RESOURCE = new LegitimateTestCase(
            "/resources/images/icons/social/facebook.svg",
            "Deeply nested static resource path",
            "Static resources often have deep directory structures that must be accepted"
    );

    // Framework-Specific Patterns
    public static final LegitimateTestCase SPRING_ACTUATOR = new LegitimateTestCase(
            "/actuator/health",
            "Spring Boot Actuator health check endpoint",
            "Spring Boot actuator endpoints are standard monitoring paths that must be accepted"
    );

    public static final LegitimateTestCase ANGULAR_ROUTE = new LegitimateTestCase(
            "/app/dashboard",
            "Angular single-page application route",
            "SPA frameworks use client-side routing patterns that must be accepted"
    );

    public static final LegitimateTestCase WORDPRESS_ADMIN = new LegitimateTestCase(
            "/wp-admin/post.php",
            "WordPress admin panel path",
            "CMS systems have standard admin paths with hyphens that must be accepted"
    );

    // Date and Time Patterns
    public static final LegitimateTestCase DATE_PATH = new LegitimateTestCase(
            "/blog/2024/12/25/christmas-post",
            "Blog post with date-based URL structure",
            "Date-based URLs are common for blogs and news sites and must be accepted"
    );

    public static final LegitimateTestCase TIMESTAMP_PATH = new LegitimateTestCase(
            "/logs/2024-12-25T10:30:00Z",
            "Log file path with ISO 8601 timestamp",
            "Timestamp-based paths with colons and T separator must be accepted for logs"
    );

    // Encoded but Legitimate Patterns
    public static final LegitimateTestCase ENCODED_SPACE = new LegitimateTestCase(
            "/search/hello%20world",
            "Search query with properly encoded space",
            "URL-encoded spaces (%20) in search queries are legitimate and must be accepted"
    );

    public static final LegitimateTestCase ENCODED_INTERNATIONAL = new LegitimateTestCase(
            "/products/caf%C3%A9",
            "Product name with encoded UTF-8 character (é)",
            "Properly encoded international characters must be accepted for i18n support"
    );

    // Special but Valid Patterns
    public static final LegitimateTestCase DOTFILE_ACCESS = new LegitimateTestCase(
            "/config/.well-known/security.txt",
            "RFC 5785 well-known URI for security information",
            ".well-known is a standard path defined by RFC 5785 that must be accepted"
    );

    public static final LegitimateTestCase SEMANTIC_VERSION = new LegitimateTestCase(
            "/releases/v2.0.0-beta.1",
            "Semantic versioning in release path",
            "Semantic version strings with hyphens and dots are legitimate version identifiers"
    );

    public static final LegitimateTestCase PACKAGE_NAMESPACE = new LegitimateTestCase(
            "/maven/com/example/my-library/1.0.0",
            "Maven/package repository path with namespace",
            "Package manager paths use slashes for namespaces which must be accepted"
    );

    // Long but Legitimate Paths
    public static final LegitimateTestCase DEEP_TAXONOMY = new LegitimateTestCase(
            "/categories/electronics/computers/laptops/gaming/high-performance",
            "E-commerce category taxonomy with deep nesting",
            "E-commerce sites have legitimate deep category hierarchies that must be accepted"
    );

    public static final LegitimateTestCase DOCUMENTATION_PATH = new LegitimateTestCase(
            "/docs/api/reference/authentication/oauth2/authorization-code-flow",
            "Technical documentation with detailed path structure",
            "Documentation sites require detailed path structures for organization"
    );

    // Query String Patterns (focusing on path component)
    public static final LegitimateTestCase PATH_WITH_EXTENSION = new LegitimateTestCase(
            "/reports/quarterly-report.pdf",
            "Document download path with file extension",
            "File downloads with extensions are standard and must be accepted"
    );

    private static final List<LegitimateTestCase> ALL_LEGITIMATE_TEST_CASES = List.of(
            REST_API_VERSION,
            REST_RESOURCE_ID,
            REST_UUID_RESOURCE,
            REST_NESTED_RESOURCES,
            STATIC_VERSIONED_ASSET,
            STATIC_HASH_ASSET,
            STATIC_NESTED_RESOURCE,
            SPRING_ACTUATOR,
            ANGULAR_ROUTE,
            WORDPRESS_ADMIN,
            DATE_PATH,
            TIMESTAMP_PATH,
            ENCODED_SPACE,
            ENCODED_INTERNATIONAL,
            DOTFILE_ACCESS,
            SEMANTIC_VERSION,
            PACKAGE_NAMESPACE,
            DEEP_TAXONOMY,
            DOCUMENTATION_PATH,
            PATH_WITH_EXTENSION
    );

    @Override
    public Iterable<LegitimateTestCase> getLegitimateTestCases() {
        return ALL_LEGITIMATE_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "Legitimate Path Patterns Database (T31)";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of legitimate path patterns including RESTful APIs, static resources, framework patterns, and deep hierarchies that must not trigger false positives";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing.
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends LegitimatePatternDatabase.ArgumentsProvider<LegitimatePathPatternsDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}