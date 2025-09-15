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

import de.cuioss.http.security.core.UrlSecurityFailureType;

import java.util.List;

/**
 * Database of Internationalized Domain Name (IDN) attack patterns with comprehensive Unicode security coverage.
 *
 * <p><strong>CRITICAL UNICODE SECURITY DATABASE:</strong> This database contains IDN-specific
 * attack patterns that exploit Unicode homograph vulnerabilities, punycode encoding exploits,
 * and visual domain spoofing techniques. Each pattern uses exact Unicode character sequences
 * that are visually deceptive to humans but distinct to security systems.</p>
 *
 * <p>These attacks exploit the visual similarity between characters from different Unicode
 * scripts to deceive users into visiting malicious websites that appear legitimate. The attacks
 * combine domain spoofing with path traversal to create sophisticated multi-vector exploits.</p>
 *
 * <h3>Attack Categories</h3>
 * <ul>
 *   <li><strong>Homograph Attacks</strong> - Visually similar characters from different scripts</li>
 *   <li><strong>Punycode Exploitation</strong> - ASCII-compatible encoding bypass techniques</li>
 *   <li><strong>Mixed Script Attacks</strong> - Combining Latin, Cyrillic, and other scripts</li>
 *   <li><strong>Unicode Normalization</strong> - Composed vs decomposed character exploits</li>
 *   <li><strong>Bidirectional Text</strong> - Right-to-left override manipulation</li>
 *   <li><strong>Invisible Characters</strong> - Zero-width and control character insertion</li>
 * </ul>
 *
 * @since 2.5
 */
public class IDNAttackDatabase implements AttackDatabase {

    // Homograph attacks - visually similar characters
    public static final AttackTestCase CYRILLIC_APPLE_HOMOGRAPH = new AttackTestCase(
            "http://аpple.com/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Homograph attack using Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061) in apple.com domain. This attack exploits visual similarity between characters from different Unicode scripts to deceive users into visiting malicious websites that appear to be legitimate apple.com while performing path traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack contains directory traversal sequences (../../../) which are detected before suspicious pattern matching due to validation priority order."
    );

    public static final AttackTestCase CYRILLIC_GOOGLE_HOMOGRAPH = new AttackTestCase(
            "http://gооgle.com/admin/../../config",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Homograph attack using Cyrillic 'о' (U+043E) instead of Latin 'o' (U+006F) in google.com domain. This creates a visually identical domain that users cannot distinguish from the legitimate Google domain, combined with path traversal to access configuration files.",
            "PATH_TRAVERSAL_DETECTED is expected due to the presence of Cyrillic characters in what appears to be a Latin domain name, indicating potential homograph spoofing combined with unauthorized directory access."
    );

    public static final AttackTestCase CYRILLIC_MICROSOFT_HOMOGRAPH = new AttackTestCase(
            "http://miсrosoft.com/../../etc/hosts",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Homograph attack using Cyrillic 'с' (U+0441) instead of Latin 'c' (U+0063) in microsoft.com domain. This attack targets users' trust in the Microsoft brand while attempting to access the system hosts file through path traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because the Cyrillic 'с' character creates a homograph spoofing attack against the Microsoft brand, combined with directory traversal patterns."
    );

    public static final AttackTestCase CYRILLIC_PAYPAL_HOMOGRAPH = new AttackTestCase(
            "http://раypal.com/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Advanced homograph attack using multiple Cyrillic characters: 'р' (U+0440) instead of Latin 'p' and 'а' (U+0430) instead of Latin 'a' in paypal.com. This targets financial services users with a highly deceptive domain combined with system file access attempts.",
            "PATH_TRAVERSAL_DETECTED is expected due to multiple Cyrillic character substitutions creating a convincing paypal.com homograph, combined with path traversal to sensitive system files."
    );

    // Punycode exploitation
    public static final AttackTestCase PUNYCODE_APPLE_ATTACK = new AttackTestCase(
            "http://xn--pple-43d.com/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Punycode exploitation attack where 'xn--pple-43d.com' is the ASCII-compatible encoding of 'аpple.com' (with Cyrillic 'а'). This bypasses ASCII-only domain filters while maintaining the visual deception, combined with path traversal to access system password files.",
            "PATH_TRAVERSAL_DETECTED is expected because punycode domains (xn--) can indicate internationalized domain name attacks, and the decoded form reveals homograph spoofing."
    );

    public static final AttackTestCase PUNYCODE_RUSSIAN_DOMAIN = new AttackTestCase(
            "http://xn--e1afmkfd.com/../../config",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Punycode attack using 'xn--e1afmkfd.com' which decodes to 'пример.com' (Russian for 'example'). This demonstrates how punycode can be used to disguise non-Latin domains while performing path traversal attacks to access configuration files.",
            "PATH_TRAVERSAL_DETECTED is expected for punycode domains that may be used to disguise the true nature of international character domains, combined with directory traversal patterns."
    );

    public static final AttackTestCase PUNYCODE_CHINESE_ATTACK = new AttackTestCase(
            "http://xn--fsq.com/admin/../../etc/hosts",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Punycode attack with 'xn--fsq.com' representing Chinese character '中' (meaning 'middle' or 'China'). This shows how single character domains can be used for attack obfuscation while accessing system files through path traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because short punycode domains often indicate suspicious internationalized domain usage, combined with administrative path traversal attempts."
    );

    // Mixed script attacks
    public static final AttackTestCase MIXED_SCRIPT_GOOGLE = new AttackTestCase(
            "http://goog1е.com/../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Mixed script attack combining Latin characters, Arabic numeral '1', and Cyrillic 'е' (U+0435) in place of Latin 'e'. This creates a domain that closely resembles 'google.com' but contains characters from multiple Unicode scripts, making detection more difficult.",
            "PATH_TRAVERSAL_DETECTED is expected because mixing scripts from different Unicode blocks (Latin + Cyrillic) in a single domain is a strong indicator of homograph spoofing attempts."
    );

    public static final AttackTestCase ARMENIAN_PERIOD_TWITTER = new AttackTestCase(
            "http://twitter․com/../../admin",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Sophisticated punctuation homograph attack using Armenian full stop '․' (U+2024) instead of period '.' (U+002E) in twitter.com domain. This creates a nearly impossible to detect visual deception while attempting administrative directory access.",
            "PATH_TRAVERSAL_DETECTED is expected because non-ASCII punctuation characters in domain names, especially those visually similar to periods, indicate advanced homograph attacks."
    );

    public static final AttackTestCase HYPHENATION_POINT_INSTAGRAM = new AttackTestCase(
            "http://instagram‧com/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Advanced punctuation attack using hyphenation point '‧' (U+2027) instead of period in instagram.com. This character is visually identical to a period in most fonts, creating perfect visual spoofing while performing path traversal attacks.",
            "PATH_TRAVERSAL_DETECTED is expected due to the use of Unicode punctuation that mimics ASCII period characters, combined with directory traversal to access sensitive system files."
    );

    // Unicode normalization bypass
    public static final AttackTestCase COMPOSED_ACCENT_CAFE = new AttackTestCase(
            "http://café.com/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Unicode normalization attack using composed character 'é' (U+00E9) in café.com. This tests whether security filters properly handle Unicode normalization forms, as this character could also be represented as 'e' + combining acute accent (U+0065 + U+0301).",
            "PATH_TRAVERSAL_DETECTED is expected because accented characters in domain names may indicate normalization bypass attempts or internationalized domain attacks."
    );

    public static final AttackTestCase DECOMPOSED_ACCENT_CAFE = new AttackTestCase(
            "http://cafe\\u0301.com/../../config",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Unicode normalization attack using decomposed form: 'e' (U+0065) + combining acute accent (U+0301) instead of composed 'é'. This tests normalization handling differences where the same visual appearance can be encoded in multiple ways, bypassing simple string matching filters.",
            "PATH_TRAVERSAL_DETECTED is expected because combining characters and escape sequences (\\u0301) in URLs often indicate attempts to bypass security filters through Unicode normalization differences."
    );

    // Right-to-left override attacks
    public static final AttackTestCase RTL_OVERRIDE_GOOGLE = new AttackTestCase(
            "http://evil‮moc.elgoog.com/../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Right-to-left override attack using RTL override character (U+202E) to visually reverse text display. The domain appears as 'evil.google.com' to users but is actually 'evil‮moc.elgoog.com', creating sophisticated visual deception combined with path traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because RTL override characters (U+202E) in domain names are strong indicators of bidirectional text spoofing attacks designed to deceive users about the true domain."
    );

    public static final AttackTestCase RTL_MIDDLE_GOOGLE = new AttackTestCase(
            "http://google‮evil.com/../../etc/hosts",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "RTL override attack with the control character placed in the middle of the domain, making 'google‮evil.com' appear as 'google.live.com' or similar to users depending on text rendering, while accessing system files through path traversal.",
            "PATH_TRAVERSAL_DETECTED is expected due to the presence of RTL override control characters within domain names, indicating bidirectional text manipulation for spoofing purposes."
    );

    // Zero-width and invisible character attacks
    public static final AttackTestCase ZERO_WIDTH_SPACE_GOOGLE = new AttackTestCase(
            "http://goo​gle.com/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Zero-width space attack using invisible character '​' (U+200B) inserted within google.com domain. This character is completely invisible to users but creates a different domain name that can bypass domain-based security filters while performing path traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because zero-width characters in domain names are indicators of steganographic attacks designed to hide malicious domains within legitimate-appearing URLs."
    );

    public static final AttackTestCase ZERO_WIDTH_NON_JOINER = new AttackTestCase(
            "http://micro‌soft.com/../../config",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Zero-width non-joiner attack using invisible character '‌' (U+200C) within microsoft.com domain. This creates a domain that appears legitimate to users but is technically different, allowing bypass of domain whitelist security while attempting configuration file access.",
            "PATH_TRAVERSAL_DETECTED is expected because zero-width non-joiner characters in domain names indicate attempts to create visually deceptive domains that bypass string-based security filters."
    );

    public static final AttackTestCase SOFT_HYPHEN_TWITTER = new AttackTestCase(
            "http://twit­ter.com/../../../admin",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Soft hyphen attack using '­' (U+00AD) character within twitter.com domain. Soft hyphens are invisible unless needed for line breaking, creating domains that appear normal to users but are different to security systems, combined with administrative directory traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because soft hyphen characters in domain names are used to create visually deceptive domains that appear legitimate while bypassing exact string matching security filters."
    );

    // Unicode confusables
    public static final AttackTestCase FULL_WIDTH_GOOGLE = new AttackTestCase(
            "http://ｇoogle.com/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Full-width character attack using full-width 'ｇ' (U+FF47) instead of regular Latin 'g' in google.com. Full-width characters are visually similar but technically different, commonly used in East Asian typography to create convincing domain spoofs.",
            "PATH_TRAVERSAL_DETECTED is expected because full-width Unicode characters in domain names often indicate attempts to create visually similar domains for spoofing purposes."
    );

    public static final AttackTestCase MATHEMATICAL_BOLD_GOOGLE = new AttackTestCase(
            "http://𝗴𝗼𝗼𝗴𝗹𝗲.com/../../config",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Mathematical bold attack using mathematical bold characters (U+1D5F4-U+1D608) to create 'google' domain. These characters appear as bold text but are technically different Unicode code points, creating sophisticated homograph attacks that bypass simple character filtering.",
            "PATH_TRAVERSAL_DETECTED is expected because mathematical Unicode characters in domain names are strong indicators of advanced homograph spoofing using specialized Unicode blocks."
    );

    public static final AttackTestCase MATHEMATICAL_ITALIC_GOOGLE = new AttackTestCase(
            "http://𝑔𝑜𝑜𝑔𝑙𝑒.com/admin/../etc/hosts",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Mathematical italic attack using mathematical italic characters (U+1D454-U+1D467) for 'google' domain. These create visually distinct but recognizable versions of Latin characters, used for sophisticated spoofing attacks against security-conscious users.",
            "PATH_TRAVERSAL_DETECTED is expected because mathematical italic Unicode characters in domains indicate advanced homograph attacks using specialized mathematical character sets."
    );

    // Complex IDN with multiple vulnerabilities
    public static final AttackTestCase PUNYCODE_PORT_TRAVERSAL = new AttackTestCase(
            "http://xn--e1afmkfd.com:8080/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Complex multi-vector attack combining punycode domain (пример.com), non-standard port 8080, and path traversal. This demonstrates how IDN attacks can be combined with other techniques to create sophisticated multi-stage attacks targeting different security layers.",
            "PATH_TRAVERSAL_DETECTED is expected because the combination of punycode domains, non-standard ports, and path traversal represents a complex multi-vector attack pattern."
    );

    public static final AttackTestCase MIXED_SCRIPT_HTTPS_TRAVERSAL = new AttackTestCase(
            "https://goog1е.com/admin/../../config",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Advanced attack combining HTTPS protocol, mixed script homograph (Latin + Cyrillic), and administrative path traversal. This shows how attackers can use SSL encryption to add legitimacy to homograph attacks while performing unauthorized file access.",
            "PATH_TRAVERSAL_DETECTED is expected because mixed script domains over HTTPS with administrative path traversal represent sophisticated social engineering combined with technical exploitation."
    );

    public static final AttackTestCase CYRILLIC_ZERO_WIDTH_TRAVERSAL = new AttackTestCase(
            "http://аpp‌le.com/../sensitive/data",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Multi-layer attack combining Cyrillic homograph 'а' (U+0430), zero-width non-joiner '‌' (U+200C), and path traversal. This creates a domain that appears as 'apple.com' to users but contains multiple deceptive Unicode elements while accessing sensitive data.",
            "PATH_TRAVERSAL_DETECTED is expected due to the combination of homograph characters and invisible Unicode characters in the domain, representing a multi-vector deception attack."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            CYRILLIC_APPLE_HOMOGRAPH,
            CYRILLIC_GOOGLE_HOMOGRAPH,
            CYRILLIC_MICROSOFT_HOMOGRAPH,
            CYRILLIC_PAYPAL_HOMOGRAPH,
            PUNYCODE_APPLE_ATTACK,
            PUNYCODE_RUSSIAN_DOMAIN,
            PUNYCODE_CHINESE_ATTACK,
            MIXED_SCRIPT_GOOGLE,
            ARMENIAN_PERIOD_TWITTER,
            HYPHENATION_POINT_INSTAGRAM,
            COMPOSED_ACCENT_CAFE,
            DECOMPOSED_ACCENT_CAFE,
            RTL_OVERRIDE_GOOGLE,
            RTL_MIDDLE_GOOGLE,
            ZERO_WIDTH_SPACE_GOOGLE,
            ZERO_WIDTH_NON_JOINER,
            SOFT_HYPHEN_TWITTER,
            FULL_WIDTH_GOOGLE,
            MATHEMATICAL_BOLD_GOOGLE,
            MATHEMATICAL_ITALIC_GOOGLE,
            PUNYCODE_PORT_TRAVERSAL,
            MIXED_SCRIPT_HTTPS_TRAVERSAL,
            CYRILLIC_ZERO_WIDTH_TRAVERSAL
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "IDN Attack Database";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of Internationalized Domain Name (IDN) attack patterns including homograph attacks, punycode exploitation, mixed scripts, Unicode normalization, bidirectional text manipulation, and invisible character insertion";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     *
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(IDNAttackDatabase.ArgumentsProvider.class)
     * void shouldRejectIDNAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<IDNAttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}