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
package de.cuioss.tools.security.http.generators.header;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for valid HTTP header values.
 * 
 * IMPROVED: Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining realistic HTTP header value patterns.
 * 
 * FRAMEWORK COMPLIANT: Uses seed-based generation without call-counter anti-pattern.
 * Reproducibility = f(seed), not f(internal_state).
 * 
 * Provides common header value examples for testing.
 */
public class ValidHTTPHeaderValueGenerator implements TypedGenerator<String> {

    // Core generation parameters
    private final TypedGenerator<String> contentTypes = Generators.fixedValues("application/json", "text/html", "application/xml", "text/plain");
    private final TypedGenerator<String> charsets = Generators.fixedValues("utf-8", "iso-8859-1", "us-ascii", "utf-16");
    private final TypedGenerator<String> encodings = Generators.fixedValues("gzip", "deflate", "br", "compress");
    private final TypedGenerator<String> languages = Generators.fixedValues("en-US", "en", "de", "fr", "es");
    private final TypedGenerator<String> browsers = Generators.fixedValues("Mozilla/5.0", "Chrome", "Safari", "Edge");
    private final TypedGenerator<String> osTypes = Generators.fixedValues("Windows NT 6.2", "Macintosh", "X11; Linux", "Android");
    private final TypedGenerator<String> connections = Generators.fixedValues("keep-alive", "close", "upgrade");
    private final TypedGenerator<String> cacheDirectives = Generators.fixedValues("no-cache", "max-age=3600", "must-revalidate", "private");
    private final TypedGenerator<String> origins = Generators.fixedValues("same-origin", "cors", "no-cors");
    private final TypedGenerator<String> ips = Generators.fixedValues("192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1");
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();
    private final TypedGenerator<Integer> ageValues = Generators.integers(60, 86400);
    private final TypedGenerator<Double> qualityValues = Generators.doubles(0.1, 1.0);

    @Override
    public String next() {
        int valueType = Generators.integers(0, 9).next();
        return switch (valueType) {
            case 0 -> generateAuthorizationValue();
            case 1 -> generateContentTypeValue();
            case 2 -> generateAcceptEncodingValue();
            case 3 -> generateAcceptLanguageValue();
            case 4 -> generateCacheControlValue();
            case 5 -> generateUserAgentValue();
            case 6 -> generateConnectionValue();
            case 7 -> generateOriginValue();
            case 8 -> generateForwardedForValue();
            case 9 -> generateMiscValue();
            default -> generateContentTypeValue();
        };
    }

    private String generateAuthorizationValue() {
        int authType = Generators.integers(0, 1).next();
        return switch (authType) {
            case 0 -> generateBearerToken();
            case 1 -> generateBasicAuth();
            default -> generateBearerToken();
        };
    }

    private String generateBearerToken() {
        String token = Generators.letterStrings(32, 64).next();
        return "Bearer " + token;
    }

    private String generateBasicAuth() {
        String credentials = Generators.letterStrings(16, 32).next();
        return "Basic " + credentials;
    }

    private String generateContentTypeValue() {
        String contentType = contentTypes.next();
        if (contextSelector.next()) {
            String charset = charsets.next();
            return contentType + "; charset=" + charset;
        }
        return contentType;
    }

    private String generateAcceptEncodingValue() {
        StringBuilder encoding = new StringBuilder();
        encoding.append(encodings.next());

        if (contextSelector.next()) {
            encoding.append(", ").append(encodings.next());
            if (contextSelector.next()) {
                encoding.append(", ").append(encodings.next());
            }
        }

        return encoding.toString();
    }

    private String generateAcceptLanguageValue() {
        String language = languages.next();
        if (contextSelector.next()) {
            double quality = qualityValues.next();
            language += ";q=" + "%.1f".formatted(quality);

            if (contextSelector.next()) {
                String secondLang = languages.next();
                double secondQuality = qualityValues.next();
                language += "," + secondLang + ";q=" + "%.1f".formatted(secondQuality);
            }
        }
        return language;
    }

    private String generateCacheControlValue() {
        String directive = cacheDirectives.next();
        if (contextSelector.next() && !directive.contains("=")) {
            int age = ageValues.next();
            return directive + ", max-age=" + age;
        }
        return directive;
    }

    private String generateUserAgentValue() {
        String browser = browsers.next();
        String os = osTypes.next();
        if ("Mozilla/5.0".equals(browser)) {
            return browser + " (compatible; " + Generators.fixedValues("MSIE 10.0", "Chrome/91.0", "Safari/537.36").next() + "; " + os + ")";
        }
        return browser + "/" + Generators.integers(80, 120).next() + ".0 (" + os + ")";
    }

    private String generateConnectionValue() {
        return connections.next();
    }

    private String generateOriginValue() {
        String origin = origins.next();
        if ("cors".equals(origin)) {
            return "https://example.com";
        }
        return origin;
    }

    private String generateForwardedForValue() {
        StringBuilder ips = new StringBuilder();
        ips.append(this.ips.next());

        if (contextSelector.next()) {
            ips.append(", ").append(this.ips.next());
        }

        return ips.toString();
    }

    private String generateMiscValue() {
        String[] miscValues = {
                "XMLHttpRequest",
                "https%3A%2F%2Fexample.com",
                "application/x-www-form-urlencoded",
                "text/css",
                "image/png"
        };
        return miscValues[Generators.integers(0, miscValues.length - 1).next()];
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}