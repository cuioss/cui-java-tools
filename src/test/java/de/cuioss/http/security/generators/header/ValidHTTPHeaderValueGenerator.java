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
package de.cuioss.http.security.generators.header;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for valid HTTP header values.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.
 * Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining realistic HTTP header value patterns.</p>
 *
 * <p>FRAMEWORK COMPLIANT: Uses seed-based generation without call-counter anti-pattern.
 * Reproducibility = f(seed), not f(internal_state).</p>
 *
 * <p>Provides common header value examples for testing validation including:
 * Authorization tokens, Content-Type, Accept headers, Cache-Control, User-Agent,
 * and various HTTP standard header values.</p>
 */
public class ValidHTTPHeaderValueGenerator implements TypedGenerator<String> {

    // Core generation parameters - all seed-based, no internal state
    private final TypedGenerator<Integer> headerTypeSelector = Generators.integers(1, 9);
    private final TypedGenerator<Integer> contentTypeSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> charsetSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> encodingSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> languageSelector = Generators.integers(1, 5);
    private final TypedGenerator<Integer> browserSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> osSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> connectionSelector = Generators.integers(1, 3);
    private final TypedGenerator<Integer> cacheDirectiveSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> originSelector = Generators.integers(1, 3);
    private final TypedGenerator<Integer> ipSelector = Generators.integers(1, 4);
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();
    private final TypedGenerator<Integer> ageValues = Generators.integers(60, 86400);
    private final TypedGenerator<Double> qualityValues = Generators.doubles(0.1, 1.0);
    private final TypedGenerator<String> tokenGenerator = Generators.letterStrings(32, 64);
    private final TypedGenerator<String> credentialsGenerator = Generators.letterStrings(16, 32);
    private final TypedGenerator<Integer> browserVersionGenerator = Generators.integers(80, 120);

    @Override
    public String next() {
        return switch (headerTypeSelector.next()) {
            case 1 -> generateAuthorizationValue();
            case 2 -> generateContentTypeValue();
            case 3 -> generateAcceptEncodingValue();
            case 4 -> generateAcceptLanguageValue();
            case 5 -> generateCacheControlValue();
            case 6 -> generateUserAgentValue();
            case 7 -> generateConnectionValue();
            case 8 -> generateOriginValue();
            case 9 -> generateForwardedForValue();
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
        String token = tokenGenerator.next();
        return "Bearer " + token;
    }

    private String generateBasicAuth() {
        String credentials = credentialsGenerator.next();
        return "Basic " + credentials;
    }

    private String generateContentTypeValue() {
        String contentType = generateContentType();
        if (contextSelector.next()) {
            String charset = generateCharset();
            return contentType + "; charset=" + charset;
        }
        return contentType;
    }

    private String generateContentType() {
        return switch (contentTypeSelector.next()) {
            case 1 -> "application/json";
            case 2 -> "text/html";
            case 3 -> "application/xml";
            case 4 -> "text/plain";
            default -> "application/json";
        };
    }

    private String generateCharset() {
        return switch (charsetSelector.next()) {
            case 1 -> "utf-8";
            case 2 -> "iso-8859-1";
            case 3 -> "us-ascii";
            case 4 -> "utf-16";
            default -> "utf-8";
        };
    }

    private String generateAcceptEncodingValue() {
        StringBuilder encoding = new StringBuilder();
        encoding.append(generateEncoding());

        if (contextSelector.next()) {
            encoding.append(", ").append(generateEncoding());
            if (contextSelector.next()) {
                encoding.append(", ").append(generateEncoding());
            }
        }

        return encoding.toString();
    }

    private String generateEncoding() {
        return switch (encodingSelector.next()) {
            case 1 -> "gzip";
            case 2 -> "deflate";
            case 3 -> "br";
            case 4 -> "compress";
            default -> "gzip";
        };
    }

    private String generateAcceptLanguageValue() {
        String language = generateLanguage();
        if (contextSelector.next()) {
            double quality = qualityValues.next();
            language += ";q=" + "%.1f".formatted(quality);

            if (contextSelector.next()) {
                String secondLang = generateLanguage();
                double secondQuality = qualityValues.next();
                language += "," + secondLang + ";q=" + "%.1f".formatted(secondQuality);
            }
        }
        return language;
    }

    private String generateLanguage() {
        return switch (languageSelector.next()) {
            case 1 -> "en-US";
            case 2 -> "en";
            case 3 -> "de";
            case 4 -> "fr";
            case 5 -> "es";
            default -> "en-US";
        };
    }

    private String generateCacheControlValue() {
        String directive = generateCacheDirective();
        if (contextSelector.next() && !directive.contains("=")) {
            int age = ageValues.next();
            return directive + ", max-age=" + age;
        }
        return directive;
    }

    private String generateCacheDirective() {
        return switch (cacheDirectiveSelector.next()) {
            case 1 -> "no-cache";
            case 2 -> "max-age=3600";
            case 3 -> "must-revalidate";
            case 4 -> "private";
            default -> "no-cache";
        };
    }

    private String generateUserAgentValue() {
        String browser = generateBrowser();
        String os = generateOS();
        if ("Mozilla/5.0".equals(browser)) {
            return browser + " (compatible; " + generateCompatibleBrowser() + "; " + os + ")";
        }
        return browser + "/" + browserVersionGenerator.next() + ".0 (" + os + ")";
    }

    private String generateBrowser() {
        return switch (browserSelector.next()) {
            case 1 -> "Mozilla/5.0";
            case 2 -> "Chrome";
            case 3 -> "Safari";
            case 4 -> "Edge";
            default -> "Mozilla/5.0";
        };
    }

    private String generateOS() {
        return switch (osSelector.next()) {
            case 1 -> "Windows NT 6.2";
            case 2 -> "Macintosh";
            case 3 -> "X11; Linux";
            case 4 -> "Android";
            default -> "Windows NT 6.2";
        };
    }

    private String generateCompatibleBrowser() {
        int compatType = Generators.integers(1, 3).next();
        return switch (compatType) {
            case 1 -> "MSIE 10.0";
            case 2 -> "Chrome/91.0";
            case 3 -> "Safari/537.36";
            default -> "MSIE 10.0";
        };
    }

    private String generateConnectionValue() {
        return switch (connectionSelector.next()) {
            case 1 -> "keep-alive";
            case 2 -> "close";
            case 3 -> "upgrade";
            default -> "keep-alive";
        };
    }

    private String generateOriginValue() {
        String origin = generateOrigin();
        if ("cors".equals(origin)) {
            return "https://example.com";
        }
        return origin;
    }

    private String generateOrigin() {
        return switch (originSelector.next()) {
            case 1 -> "same-origin";
            case 2 -> "cors";
            case 3 -> "no-cors";
            default -> "same-origin";
        };
    }

    private String generateForwardedForValue() {
        StringBuilder ips = new StringBuilder();
        ips.append(generateIP());

        if (contextSelector.next()) {
            ips.append(", ").append(generateIP());
        }

        return ips.toString();
    }

    private String generateIP() {
        return switch (ipSelector.next()) {
            case 1 -> "192.168.1.1";
            case 2 -> "10.0.0.1";
            case 3 -> "172.16.0.1";
            case 4 -> "127.0.0.1";
            default -> "192.168.1.1";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}