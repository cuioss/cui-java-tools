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
package de.cuioss.tools.security.http.generators.injection;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generates homograph attack patterns for security testing.
 * 
 * <p>
 * This generator creates attack patterns that use Unicode homograph characters
 * (visually similar characters from different scripts) to create deceptive URLs
 * and bypass security controls. Homograph attacks exploit the fact that many
 * Unicode characters look identical or very similar to ASCII characters but
 * have different code points, allowing attackers to create convincing spoofs
 * of legitimate domains, file paths, and system commands.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>Cyrillic homographs (а, о, р, с, е, х → a, o, p, c, e, x)</li>
 *   <li>Greek homographs (α, ο, ρ, υ → a, o, p, u)</li>
 *   <li>Mathematical script homographs (𝐚, 𝐨, 𝐩 → a, o, p)</li>
 *   <li>Fullwidth character homographs (ａ, ｏ, ｐ → a, o, p)</li>
 *   <li>Armenian, Georgian, and other script homographs</li>
 *   <li>Mixed script combinations for maximum deception</li>
 *   <li>Domain spoofing attacks (apple.com → аpple.com)</li>
 *   <li>File extension spoofing (.exe → .ехе)</li>
 *   <li>System command spoofing (admin → аdmin)</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - Security Misconfiguration</li>
 *   <li>CWE-20: Improper Input Validation</li>
 *   <li>CWE-178: Improper Handling of Case Sensitivity</li>
 *   <li>CWE-179: Incorrect Behavior Order: Early Validation</li>
 *   <li>Unicode Technical Standard #39 (Unicode Security Mechanisms)</li>
 *   <li>RFC 3490 - Internationalizing Domain Names in Applications (IDNA)</li>
 *   <li>Unicode Consortium Security Considerations</li>
 * </ul>
 * 
 * Implements: Generator for Task T9 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
public class HomographAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> baseTargetGen = Generators.fixedValues(
            "admin",
            "root",
            "user",
            "config",
            "system",
            "login",
            "password",
            "secure",
            "private",
            "secret",
            "apple.com",
            "google.com",
            "microsoft.com",
            "github.com",
            "example.org",
            ".exe",
            ".pdf",
            ".doc",
            ".zip",
            "script",
            "alert",
            "eval",
            "exec",
            "../",
            "../../",
            "file://",
            "javascript:",
            "data:"
    );

    private final TypedGenerator<String> homographTypeGen = Generators.fixedValues(
            "cyrillic_basic",           // Basic Cyrillic lookalikes
            "cyrillic_extended",        // Extended Cyrillic homographs
            "greek_basic",              // Basic Greek homographs
            "greek_extended",           // Extended Greek lookalikes
            "mathematical_script",      // Mathematical script variants
            "fullwidth_characters",     // Fullwidth Unicode characters
            "armenian_homographs",      // Armenian script lookalikes
            "georgian_homographs",      // Georgian script lookalikes
            "mixed_script_sophisticated", // Sophisticated mixed scripts
            "domain_spoofing",          // Specific domain spoofing patterns
            "file_extension_spoofing",  // File extension spoofing
            "system_command_spoofing"   // System command spoofing
    );

    @Override
    public String next() {
        String baseTarget = baseTargetGen.next();
        String homographType = homographTypeGen.next();

        return switch (homographType) {
            case "cyrillic_basic" -> applyCyrillicBasicHomographs(baseTarget);
            case "cyrillic_extended" -> applyCyrillicExtendedHomographs(baseTarget);
            case "greek_basic" -> applyGreekBasicHomographs(baseTarget);
            case "greek_extended" -> applyGreekExtendedHomographs(baseTarget);
            case "mathematical_script" -> applyMathematicalScriptHomographs(baseTarget);
            case "fullwidth_characters" -> applyFullwidthHomographs(baseTarget);
            case "armenian_homographs" -> applyArmenianHomographs(baseTarget);
            case "georgian_homographs" -> applyGeorgianHomographs(baseTarget);
            case "mixed_script_sophisticated" -> applyMixedScriptSophisticated(baseTarget);
            case "domain_spoofing" -> createDomainSpoofingAttack(baseTarget);
            case "file_extension_spoofing" -> createFileExtensionSpoofing(baseTarget);
            case "system_command_spoofing" -> createSystemCommandSpoofing(baseTarget);
            default -> baseTarget;
        };
    }

    /**
     * Apply basic Cyrillic homographs (most common and effective).
     */
    private String applyCyrillicBasicHomographs(String target) {
        return target.replace("a", "\u0430")     // а (Cyrillic small letter a)
                .replace("o", "\u043E")           // о (Cyrillic small letter o)
                .replace("p", "\u0440")           // р (Cyrillic small letter p)
                .replace("c", "\u0441")           // с (Cyrillic small letter c)
                .replace("e", "\u0435")           // е (Cyrillic small letter ie)
                .replace("x", "\u0445")           // х (Cyrillic small letter kha)
                .replace("y", "\u0443")           // у (Cyrillic small letter u)
                .replace("s", "\u0455")           // ѕ (Cyrillic small letter dze)
                .replace("i", "\u0456")           // і (Cyrillic small letter byelorussian-ukrainian i)
                .replace("j", "\u0458");          // ј (Cyrillic small letter je)
    }

    /**
     * Apply extended Cyrillic homographs (less common but still deceptive).
     */
    private String applyCyrillicExtendedHomographs(String target) {
        return target.replace("A", "\u0410")     // А (Cyrillic capital letter a)
                .replace("B", "\u0412")           // В (Cyrillic capital letter ve)
                .replace("C", "\u0421")           // С (Cyrillic capital letter es)
                .replace("E", "\u0415")           // Е (Cyrillic capital letter ie)
                .replace("H", "\u041D")           // Н (Cyrillic capital letter en)
                .replace("K", "\u041A")           // К (Cyrillic capital letter ka)
                .replace("M", "\u041C")           // М (Cyrillic capital letter em)
                .replace("O", "\u041E")           // О (Cyrillic capital letter o)
                .replace("P", "\u0420")           // Р (Cyrillic capital letter er)
                .replace("T", "\u0422")           // Т (Cyrillic capital letter te)
                .replace("X", "\u0425")           // Х (Cyrillic capital letter kha)
                .replace("Y", "\u0423");          // У (Cyrillic capital letter u)
    }

    /**
     * Apply basic Greek homographs.
     */
    private String applyGreekBasicHomographs(String target) {
        return target.replace("a", "\u03B1")     // α (Greek small letter alpha)
                .replace("o", "\u03BF")           // ο (Greek small letter omicron)
                .replace("p", "\u03C1")           // ρ (Greek small letter rho)
                .replace("u", "\u03C5")           // υ (Greek small letter upsilon)
                .replace("v", "\u03BD")           // ν (Greek small letter nu)
                .replace("y", "\u03C5")           // υ (Greek small letter upsilon)
                .replace("x", "\u03C7");          // χ (Greek small letter chi)
    }

    /**
     * Apply extended Greek homographs.
     */
    private String applyGreekExtendedHomographs(String target) {
        return target.replace("A", "\u0391")     // Α (Greek capital letter alpha)
                .replace("B", "\u0392")           // Β (Greek capital letter beta)
                .replace("E", "\u0395")           // Ε (Greek capital letter epsilon)
                .replace("H", "\u0397")           // Η (Greek capital letter eta)
                .replace("I", "\u0399")           // Ι (Greek capital letter iota)
                .replace("K", "\u039A")           // Κ (Greek capital letter kappa)
                .replace("M", "\u039C")           // Μ (Greek capital letter mu)
                .replace("N", "\u039D")           // Ν (Greek capital letter nu)
                .replace("O", "\u039F")           // Ο (Greek capital letter omicron)
                .replace("P", "\u03A1")           // Ρ (Greek capital letter rho)
                .replace("T", "\u03A4")           // Τ (Greek capital letter tau)
                .replace("X", "\u03A7")           // Χ (Greek capital letter chi)
                .replace("Y", "\u03A5")           // Υ (Greek capital letter upsilon)
                .replace("Z", "\u0396");          // Ζ (Greek capital letter zeta)
    }

    /**
     * Apply mathematical script homographs.
     */
    private String applyMathematicalScriptHomographs(String target) {
        return target.replace("a", "\uD835\uDC1A")     // 𝐚 (Mathematical bold small a)
                .replace("o", "\uD835\uDC28")           // 𝐨 (Mathematical bold small o)
                .replace("p", "\uD835\uDC29")           // 𝐩 (Mathematical bold small p)
                .replace("c", "\uD835\uDC1C")           // 𝐜 (Mathematical bold small c)
                .replace("e", "\uD835\uDC1E")           // 𝐞 (Mathematical bold small e)
                .replace("i", "\uD835\uDC22")           // 𝐢 (Mathematical bold small i)
                .replace("n", "\uD835\uDC27")           // 𝐧 (Mathematical bold small n)
                .replace("s", "\uD835\uDC2C")           // 𝐬 (Mathematical bold small s)
                .replace("t", "\uD835\uDC2D");          // 𝐭 (Mathematical bold small t)
    }

    /**
     * Apply fullwidth character homographs.
     */
    private String applyFullwidthHomographs(String target) {
        return target.replace("a", "\uFF41")     // ａ (Fullwidth Latin small letter a)
                .replace("o", "\uFF4F")           // ｏ (Fullwidth Latin small letter o)
                .replace("p", "\uFF50")           // ｐ (Fullwidth Latin small letter p)
                .replace("c", "\uFF43")           // ｃ (Fullwidth Latin small letter c)
                .replace("e", "\uFF45")           // ｅ (Fullwidth Latin small letter e)
                .replace("i", "\uFF49")           // ｉ (Fullwidth Latin small letter i)
                .replace("n", "\uFF4E")           // ｎ (Fullwidth Latin small letter n)
                .replace("s", "\uFF53")           // ｓ (Fullwidth Latin small letter s)
                .replace("t", "\uFF54")           // ｔ (Fullwidth Latin small letter t)
                .replace("m", "\uFF4D")           // ｍ (Fullwidth Latin small letter m)
                .replace(".", "\uFF0E")           // ． (Fullwidth full stop)
                .replace("/", "\uFF0F");          // ／ (Fullwidth solidus)
    }

    /**
     * Apply Armenian homographs.
     */
    private String applyArmenianHomographs(String target) {
        return target.replace("o", "\u0585")     // օ (Armenian small letter oh)
                .replace("p", "\u0583")           // փ (Armenian small letter piwr)
                .replace("u", "\u0578")           // ո (Armenian small letter vo)
                .replace("n", "\u0578");          // ո (Armenian small letter vo - looks like n)
    }

    /**
     * Apply Georgian homographs.
     */
    private String applyGeorgianHomographs(String target) {
        return target.replace("o", "\u10DD")     // ო (Georgian letter on)
                .replace("g", "\u10D2")           // გ (Georgian letter gan)
                .replace("p", "\u10DE");          // პ (Georgian letter par)
    }

    /**
     * Apply sophisticated mixed script homographs for maximum deception.
     */
    private String applyMixedScriptSophisticated(String target) {
        StringBuilder result = new StringBuilder();
        boolean useCyrillic = true;

        for (char c : target.toCharArray()) {
            if (Character.isLetter(c)) {
                if (useCyrillic) {
                    // Use Cyrillic for some characters
                    switch (c) {
                        case 'a' -> result.append('\u0430');
                        case 'o' -> result.append('\u043E');
                        case 'p' -> result.append('\u0440');
                        case 'c' -> result.append('\u0441');
                        case 'e' -> result.append('\u0435');
                        default -> result.append(c);
                    }
                } else {
                    // Use Greek for other characters
                    switch (c) {
                        case 'a' -> result.append('\u03B1');
                        case 'o' -> result.append('\u03BF');
                        case 'p' -> result.append('\u03C1');
                        case 'u' -> result.append('\u03C5');
                        case 'v' -> result.append('\u03BD');
                        default -> result.append(c);
                    }
                }
                useCyrillic = !useCyrillic; // Alternate between scripts
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Create domain spoofing attacks with homographs.
     */
    private String createDomainSpoofingAttack(String target) {
        if (target.contains(".com") || target.contains(".org") || target.contains(".")) {
            // Apply homographs to domain names for spoofing
            String spoofed = applyCyrillicBasicHomographs(target);

            // Add some additional sophisticated substitutions
            spoofed = spoofed.replace("l", "\u04CF")     // ӏ (Cyrillic small letter palochka)
                    .replace("I", "\u04C0")              // Ӏ (Cyrillic capital letter palochka)
                    .replace("g", "\u0261")              // ɡ (Latin small letter script g)
                    .replace(".", "\u06D4");             // ۔ (Arabic full stop)
            
            return spoofed;
        }
        return applyCyrillicBasicHomographs(target);
    }

    /**
     * Create file extension spoofing attacks.
     */
    private String createFileExtensionSpoofing(String target) {
        if (target.startsWith(".")) {
            // Apply homographs to file extensions
            return applyCyrillicBasicHomographs(target)
                    .replace("x", "\u0445")              // х (Cyrillic kha for 'x' in .exe)
                    .replace("d", "\u0501")              // ԁ (Cyrillic small letter komi de)
                    .replace("f", "\u0493");             // ғ (Cyrillic small letter ghe with stroke)
        }
        return target + applyCyrillicBasicHomographs(".exe");
    }

    /**
     * Create system command spoofing attacks.
     */
    private String createSystemCommandSpoofing(String target) {
        // Create convincing spoofs of system commands and sensitive terms
        String spoofed = applyCyrillicBasicHomographs(target);

        // Add some additional sophisticated character substitutions
        spoofed = spoofed.replace("m", "\u043C")         // м (Cyrillic small letter em)
                .replace("n", "\u043F")                  // п (Cyrillic small letter pe - looks like n)
                .replace("r", "\u0433")                  // г (Cyrillic small letter ghe - looks like r)
                .replace("g", "\u0434")                  // д (Cyrillic small letter de - looks like g)
                .replace("l", "\u04CF")                  // ӏ (Cyrillic small letter palochka - looks like l)
                .replace("t", "\u0442");                 // т (Cyrillic small letter te)
        
        return spoofed;
    }

    /**
     * Check if a string contains homograph characters.
     * 
     * @param input The string to check
     * @return true if the string contains potential homograph characters
     */
    public boolean containsHomographs(String input) {
        for (char c : input.toCharArray()) {
            // Check for common homograph character ranges
            if (isCyrillicHomograph(c) || isGreekHomograph(c) ||
                    isMathematicalHomograph(c) || isFullwidthHomograph(c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a character is a Cyrillic homograph.
     */
    private boolean isCyrillicHomograph(char c) {
        // Common Cyrillic homographs
        return c == '\u0430' || c == '\u043E' || c == '\u0440' || c == '\u0441' ||
                c == '\u0435' || c == '\u0445' || c == '\u0443' || c == '\u0455' ||
                c == '\u0456' || c == '\u0458' || c == '\u0410' || c == '\u0412' ||
                c == '\u0421' || c == '\u0415' || c == '\u041D' || c == '\u041A' ||
                c == '\u041C' || c == '\u041E' || c == '\u0420' || c == '\u0422' ||
                c == '\u0425' || c == '\u0423';
    }

    /**
     * Check if a character is a Greek homograph.
     */
    private boolean isGreekHomograph(char c) {
        // Common Greek homographs
        return c == '\u03B1' || c == '\u03BF' || c == '\u03C1' || c == '\u03C5' ||
                c == '\u03BD' || c == '\u03C7' || c == '\u0391' || c == '\u0392' ||
                c == '\u0395' || c == '\u0397' || c == '\u0399' || c == '\u039A' ||
                c == '\u039C' || c == '\u039D' || c == '\u039F' || c == '\u03A1' ||
                c == '\u03A4' || c == '\u03A7' || c == '\u03A5' || c == '\u0396';
    }

    /**
     * Check if a character is a mathematical script homograph.
     */
    private boolean isMathematicalHomograph(char c) {
        // Mathematical bold characters (represented as surrogate pairs)
        int codePoint = (int) c;
        return codePoint >= 0x1D400 && codePoint <= 0x1D7FF;
    }

    /**
     * Check if a character is a fullwidth homograph.
     */
    private boolean isFullwidthHomograph(char c) {
        // Fullwidth characters
        return c >= '\uFF01' && c <= '\uFF5E';
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}