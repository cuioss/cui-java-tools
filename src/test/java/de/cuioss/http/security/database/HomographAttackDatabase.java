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
 * Database of Unicode homograph attack patterns with comprehensive character substitution coverage.
 *
 * <p><strong>CRITICAL UNICODE HOMOGRAPH DATABASE:</strong> This database contains Unicode
 * homograph attack patterns that exploit visual character similarity across different
 * writing systems. Each pattern uses exact Unicode character pairs that are visually
 * identical or nearly identical to humans but have different code points.</p>
 *
 * <p>These attacks exploit the visual confusion between characters from different Unicode
 * scripts (Latin, Cyrillic, Greek, Mathematical, etc.) to bypass security filters that
 * rely on exact string matching while appearing legitimate to human users.</p>
 *
 * <h3>Homograph Categories</h3>
 * <ul>
 *   <li><strong>Cyrillic Homographs</strong> - а, о, р, с, е, х → a, o, p, c, e, x</li>
 *   <li><strong>Greek Homographs</strong> - α, ο, ρ, υ → a, o, p, u</li>
 *   <li><strong>Mathematical Script</strong> - 𝐚, 𝐨, 𝐩 → a, o, p (Unicode Mathematical Bold)</li>
 *   <li><strong>Fullwidth Characters</strong> - ａ, ｏ, ｐ → a, o, p (East Asian typography)</li>
 *   <li><strong>Armenian Homographs</strong> - օ, փ, ո → o, p, n</li>
 *   <li><strong>Georgian Homographs</strong> - ო, გ, პ → o, g, p</li>
 * </ul>
 *
 * <h3>Security Standards</h3>
 * <ul>
 *   <li><strong>Unicode Technical Standard #39</strong> - Unicode Security Mechanisms</li>
 *   <li><strong>RFC 3490</strong> - Internationalizing Domain Names in Applications (IDNA)</li>
 *   <li><strong>CWE-20</strong> - Improper Input Validation via homograph bypass</li>
 *   <li><strong>CWE-178</strong> - Case sensitivity bypass through character substitution</li>
 * </ul>
 *
 * @since 2.5
 */
public class HomographAttackDatabase implements AttackDatabase {

    // Cyrillic Basic Homographs - Most Common and Effective
    public static final AttackTestCase CYRILLIC_ADMIN_ATTACK = new AttackTestCase(
            "аdmin",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Homograph attack using Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061) in 'admin'. This creates a visually identical administrative term that can bypass exact string matching security filters while appearing legitimate to users attempting administrative access.",
            "INVALID_CHARACTER is expected because Cyrillic characters in what appears to be a Latin administrative term indicates potential homograph spoofing for privilege escalation bypass."
    );

    public static final AttackTestCase CYRILLIC_ROOT_ATTACK = new AttackTestCase(
            "rооt",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Homograph attack using Cyrillic 'о' (U+043E) instead of Latin 'o' (U+006F) in 'root'. This targets the root user account with visually deceptive characters that maintain the appearance of the legitimate root username while using different Unicode code points.",
            "INVALID_CHARACTER is expected due to the presence of Cyrillic characters in what appears to be a system administration username, indicating homograph-based authentication bypass attempts."
    );

    public static final AttackTestCase CYRILLIC_PASSWORD_ATTACK = new AttackTestCase(
            "раѕѕword",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Complex homograph attack using multiple Cyrillic substitutions: 'р' (U+0440) for 'p', 'а' (U+0430) for 'a', and 'ѕ' (U+0455) for 's' in 'password'. This demonstrates sophisticated multi-character homograph attacks targeting authentication systems.",
            "INVALID_CHARACTER is expected because multiple Cyrillic character substitutions in a security-sensitive term like 'password' represent advanced homograph spoofing techniques."
    );

    public static final AttackTestCase CYRILLIC_SYSTEM_ATTACK = new AttackTestCase(
            "ѕуѕtеm",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Advanced homograph attack using Cyrillic 'ѕ' (U+0455), 'у' (U+0443), and 'е' (U+0435) in 'system'. This targets system-level access controls with multiple visually deceptive character substitutions that maintain readability while bypassing string-based filters.",
            "INVALID_CHARACTER is expected because the combination of multiple Cyrillic characters in a system administration term indicates sophisticated homograph-based security bypass attempts."
    );

    // Domain Spoofing with Homographs
    public static final AttackTestCase APPLE_DOMAIN_SPOOFING = new AttackTestCase(
            "аpple.com",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Domain spoofing attack using Cyrillic 'а' (U+0430) instead of Latin 'a' in apple.com. This creates a domain that is visually identical to the legitimate Apple domain but technically different, allowing attackers to register deceptive domains for phishing and fraud.",
            "INVALID_CHARACTER is expected because Cyrillic characters in what appears to be a major brand domain (.com) indicates potential domain spoofing for phishing or trademark abuse."
    );

    public static final AttackTestCase GOOGLE_DOMAIN_SPOOFING = new AttackTestCase(
            "gооgle.com",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Domain spoofing using Cyrillic 'о' (U+043E) for both 'o' characters in google.com. This demonstrates how multiple identical homograph substitutions can create convincing domain spoofs that are virtually impossible for users to distinguish from legitimate domains.",
            "INVALID_CHARACTER is expected due to multiple Cyrillic 'о' characters in a major technology brand domain, indicating systematic homograph spoofing for potential phishing attacks."
    );

    public static final AttackTestCase MICROSOFT_DOMAIN_SPOOFING = new AttackTestCase(
            "miсroѕoft.com",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Sophisticated domain spoofing using Cyrillic 'с' (U+0441) and 'ѕ' (U+0455) in microsoft.com. This targets one of the world's largest technology companies with visually perfect character substitutions that maintain complete visual fidelity.",
            "INVALID_CHARACTER is expected because multiple Cyrillic character substitutions in the Microsoft brand domain represent high-value target spoofing for corporate phishing attacks."
    );

    // Greek Homographs
    public static final AttackTestCase GREEK_ALPHA_ADMIN = new AttackTestCase(
            "αdmin",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Greek homograph attack using Greek small letter alpha 'α' (U+03B1) instead of Latin 'a' in 'admin'. This demonstrates how Greek script characters can be used for administrative privilege bypass through visual character deception.",
            "INVALID_CHARACTER is expected because Greek characters in administrative terms indicate potential homograph-based authentication or authorization bypass techniques."
    );

    public static final AttackTestCase GREEK_OMICRON_ROOT = new AttackTestCase(
            "rοοt",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Greek homograph attack using Greek small letter omicron 'ο' (U+03BF) for 'o' characters in 'root'. This shows how Greek script can provide alternative homograph options when Cyrillic substitutions might be detected or filtered.",
            "INVALID_CHARACTER is expected due to Greek characters in system administration usernames, representing homograph spoofing for root privilege escalation attempts."
    );

    public static final AttackTestCase GREEK_RHO_PASSWORD = new AttackTestCase(
            "ρassword",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Greek homograph using Greek small letter rho 'ρ' (U+03C1) instead of Latin 'p' in 'password'. This demonstrates the Greek script's effectiveness for creating deceptive authentication terms that bypass Latin-based security filters.",
            "INVALID_CHARACTER is expected because Greek characters in security-sensitive terms like 'password' indicate potential authentication system bypass through homograph deception."
    );

    // Mathematical Script Homographs
    public static final AttackTestCase MATHEMATICAL_BOLD_ADMIN = new AttackTestCase(
            "𝐚dmin",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Mathematical script homograph using Mathematical bold small 'a' (U+1D41A) in 'admin'. This demonstrates how Unicode mathematical characters can be used for sophisticated visual deception in administrative contexts while bypassing standard character filters.",
            "INVALID_CHARACTER is expected because mathematical Unicode characters in administrative terms represent advanced homograph techniques using specialized Unicode blocks for security bypass."
    );

    public static final AttackTestCase MATHEMATICAL_SCRIPT_CONFIG = new AttackTestCase(
            "𝐜𝐨𝐧𝐟𝐢𝐠",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Complete mathematical script transformation of 'config' using Mathematical bold characters. This shows how entire words can be transformed using consistent mathematical character sets while maintaining perfect visual similarity for configuration access bypass.",
            "INVALID_CHARACTER is expected because complete mathematical Unicode transformation of configuration terms indicates sophisticated homograph attacks targeting system configuration access."
    );

    // Fullwidth Character Homographs
    public static final AttackTestCase FULLWIDTH_SECURE = new AttackTestCase(
            "ｓｅｃｕｒｅ",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Fullwidth character attack transforming 'secure' using East Asian fullwidth Latin characters (U+FF01-FF5E range). These characters are designed for Asian typography but appear identical to regular Latin characters, creating perfect visual homographs.",
            "INVALID_CHARACTER is expected because fullwidth characters in security-related terms indicate East Asian typography-based homograph attacks for security context bypass."
    );

    public static final AttackTestCase FULLWIDTH_LOGIN = new AttackTestCase(
            "ｌｏｇｉｎ",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Fullwidth character homograph of 'login' using complete East Asian typography transformation. This demonstrates how fullwidth characters can create authentication bypass opportunities while maintaining complete visual compatibility with standard Latin text.",
            "INVALID_CHARACTER is expected due to fullwidth character usage in authentication terms, representing typography-based homograph spoofing for login system bypass."
    );

    // File Extension Spoofing
    public static final AttackTestCase CYRILLIC_EXE_SPOOFING = new AttackTestCase(
            ".ехе",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "File extension spoofing using Cyrillic 'е' (U+0435) and 'х' (U+0445) in '.exe'. This creates a file extension that appears identical to the dangerous '.exe' extension but uses different Unicode characters, potentially bypassing file type restrictions.",
            "INVALID_CHARACTER is expected because Cyrillic characters in executable file extensions indicate potential file type filtering bypass through homograph deception."
    );

    public static final AttackTestCase CYRILLIC_PDF_SPOOFING = new AttackTestCase(
            ".рdf",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "File extension homograph using Cyrillic 'р' (U+0440) in '.pdf'. This demonstrates how document format extensions can be spoofed using visually identical characters to bypass file type security controls while appearing as legitimate PDF files.",
            "INVALID_CHARACTER is expected because Cyrillic characters in document file extensions represent file type spoofing attempts using homograph character substitution."
    );

    // Mixed Script Sophisticated Attacks
    public static final AttackTestCase MIXED_SCRIPT_APPLE = new AttackTestCase(
            "αрple.com",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Sophisticated mixed script attack combining Greek alpha 'α' and Cyrillic 'р' in apple.com domain. This demonstrates advanced homograph techniques that mix different Unicode scripts to create maximum visual deception while evading single-script detection methods.",
            "INVALID_CHARACTER is expected because mixing multiple Unicode scripts (Greek + Cyrillic) in major brand domains indicates sophisticated multi-vector homograph spoofing attacks."
    );

    public static final AttackTestCase MIXED_SCRIPT_GITHUB = new AttackTestCase(
            "ɡithub.сοm",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Complex mixed script attack using Latin script 'ɡ' (U+0261), Cyrillic 'с', and Greek 'ο' in github.com. This shows how multiple Unicode scripts can be strategically combined to target developer platforms with sophisticated homograph deception techniques.",
            "INVALID_CHARACTER is expected due to the strategic combination of Latin script, Cyrillic, and Greek characters in a major development platform domain, indicating advanced homograph targeting."
    );

    // System Command Spoofing
    public static final AttackTestCase CYRILLIC_SCRIPT_COMMAND = new AttackTestCase(
            "ѕсript",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "System command spoofing using Cyrillic 'ѕ' (U+0455) and 'с' (U+0441) in 'script'. This targets JavaScript and system scripting contexts with homograph characters that can bypass command filtering while maintaining the appearance of legitimate script commands.",
            "INVALID_CHARACTER is expected because Cyrillic characters in scripting commands indicate potential code execution bypass through homograph substitution in script execution contexts."
    );

    public static final AttackTestCase CYRILLIC_EXEC_COMMAND = new AttackTestCase(
            "ехес",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Executive command spoofing using Cyrillic 'е' and 'с' in 'exec'. This demonstrates homograph attacks targeting system execution commands that could bypass command injection filters while appearing as legitimate system execution calls.",
            "INVALID_CHARACTER is expected because Cyrillic characters in system execution commands represent potential command injection bypass through executive command homograph spoofing."
    );

    // Protocol and Path Spoofing
    public static final AttackTestCase JAVASCRIPT_PROTOCOL_SPOOFING = new AttackTestCase(
            "jаvаscript:",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "JavaScript protocol spoofing using Cyrillic 'а' (U+0430) characters in 'javascript:' URI scheme. This can bypass XSS filters that block the javascript: protocol by using visually identical but technically different characters in malicious script execution attempts.",
            "INVALID_CHARACTER is expected because Cyrillic characters in JavaScript URI schemes indicate potential XSS filter bypass through protocol homograph spoofing for script injection."
    );

    public static final AttackTestCase FILE_PROTOCOL_SPOOFING = new AttackTestCase(
            "filе://",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "File protocol spoofing using Cyrillic 'е' (U+0435) in 'file://' URI scheme. This demonstrates how local file access protocols can be spoofed using homograph characters to potentially bypass protocol-based security restrictions.",
            "INVALID_CHARACTER is expected because Cyrillic characters in file URI schemes represent potential local file access bypass through protocol homograph deception."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            CYRILLIC_ADMIN_ATTACK,
            CYRILLIC_ROOT_ATTACK,
            CYRILLIC_PASSWORD_ATTACK,
            CYRILLIC_SYSTEM_ATTACK,
            APPLE_DOMAIN_SPOOFING,
            GOOGLE_DOMAIN_SPOOFING,
            MICROSOFT_DOMAIN_SPOOFING,
            GREEK_ALPHA_ADMIN,
            GREEK_OMICRON_ROOT,
            GREEK_RHO_PASSWORD,
            MATHEMATICAL_BOLD_ADMIN,
            MATHEMATICAL_SCRIPT_CONFIG,
            FULLWIDTH_SECURE,
            FULLWIDTH_LOGIN,
            CYRILLIC_EXE_SPOOFING,
            CYRILLIC_PDF_SPOOFING,
            MIXED_SCRIPT_APPLE,
            MIXED_SCRIPT_GITHUB,
            CYRILLIC_SCRIPT_COMMAND,
            CYRILLIC_EXEC_COMMAND,
            JAVASCRIPT_PROTOCOL_SPOOFING,
            FILE_PROTOCOL_SPOOFING
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "Homograph Attack Database";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of Unicode homograph attack patterns including Cyrillic, Greek, Mathematical, and Fullwidth character substitutions for domain spoofing, command injection, and authentication bypass";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     *
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(HomographAttackDatabase.ArgumentsProvider.class)
     * void shouldRejectHomographAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<HomographAttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}