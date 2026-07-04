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
package de.cuioss.tools.net;

import de.cuioss.tools.logging.CuiLogger;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

import java.net.IDN;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

/**
 * <p>
 * Utility class to handle IDN email addresses.
 * </p>
 * See
 * <ul>
 * <li><a href=
 * "https://docs.oracle.com/javase/tutorial/i18n/network/idn.html">https://docs.oracle.com/
 * javase/tutorial/i18n/network/idn.html</a></li>
 * <li><a href=
 * "https://de.wikipedia.org/wiki/Internationalisierter_Domainname">https://de.wikipedia.org
 * /wiki/Internationalisierter_Domainname</a></li>
 * <li><a href=
 * "https://en.wikipedia.org/wiki/Internationalized_domain_name">https://en.wikipedia.org/
 * wiki/Internationalized_domain_name</a></li>
 * </ul>
 *
 * @author Matthias Walliczek
 */
@UtilityClass
public class IDNInternetAddress {

    private static final CuiLogger LOGGER = new CuiLogger(IDNInternetAddress.class);

    /**
     * RFC 5321 limits the local part to 64 octets, the domain may be up to 255
     * octets. Display-name segments are not length-limited.
     */
    private static final Pattern addressPatternWithDisplayName = Pattern
            .compile("([^<]*)<(.{1,64})@(.{1,255})>([^>]*)");

    private static final Pattern addressPattern = Pattern.compile("(.{1,64})@(.{1,255})");

    /**
     * Encode the domain part of an email address
     *
     * @param completeAddress the address to encode in RFC822 format
     * @return the encoded address in RFC822 format
     */
    public static String encode(@NonNull final String completeAddress) {
        return encode(completeAddress, untrustedHtml -> untrustedHtml);
    }

    /**
     * Encodes the given address and sanitizes the elements with the provided
     * sanitizer. It takes care on the special elements like {@code <>} by not
     * trying to sanitize them.
     *
     * @param completeAddress to be encoded
     * @param sanitizer       to be passed as UnaryOperator
     * @return the sanitized and encoded address.
     */
    public static String encode(@NonNull final String completeAddress, UnaryOperator<String> sanitizer) {
        var matcher = addressPatternWithDisplayName.matcher(completeAddress);
        if (matcher.matches()) {
            return sanitizer.apply(matcher.group(1)) + "<" + sanitizer.apply(matcher.group(2)) + "@"
                    + sanitizer.apply(toAsciiSafely(matcher.group(3))) + ">" + sanitizer.apply(matcher.group(4));
        }
        matcher = addressPattern.matcher(completeAddress);
        if (matcher.matches()) {
            return sanitizer.apply(matcher.group(1)) + "@" + sanitizer.apply(toAsciiSafely(matcher.group(2)));
        }
        return sanitizer.apply(completeAddress);
    }

    /**
     * {@link IDN#toASCII(String)} throws an (undocumented) IllegalArgumentException
     * for domains that match the address patterns but are invalid for IDN (e.g.
     * empty labels like {@code domain..com}). Fall back to the unconverted domain
     * in that case, keeping this utility robust against untrusted input.
     */
    private static String toAsciiSafely(final String domain) {
        try {
            return IDN.toASCII(domain);
        } catch (IllegalArgumentException e) {
            LOGGER.trace(e, "IDN.toASCII failed for domain '%s', using unconverted value", domain);
            return domain;
        }
    }

    /**
     * Decode the domain part of an email address
     *
     * @param completeAddress the address to decode in RFC822 format
     * @return the decoded address in RFC822 format
     */
    public static String decode(@NonNull final String completeAddress) {
        return decode(completeAddress, untrustedHtml -> untrustedHtml);
    }

    /**
     * Decodes the given address and sanitizes the elements with the provided
     * sanitizer.
     * It takes care of the special elements like &lt;&gt; by not trying to
     * sanitize them.
     *
     * @param completeAddress tp be decoded
     * @param sanitizer       to be passed as UnaryOperator
     * @return the sanitized and decoded address.
     */
    public static String decode(@NonNull final String completeAddress, UnaryOperator<String> sanitizer) {
        var matcher = addressPatternWithDisplayName.matcher(completeAddress);
        if (matcher.matches()) {
            return sanitizer.apply(matcher.group(1)) + "<" + sanitizer.apply(matcher.group(2)) + "@"
                    + sanitizer.apply(IDN.toUnicode(matcher.group(3))) + ">" + sanitizer.apply(matcher.group(4));
        }
        matcher = addressPattern.matcher(completeAddress);
        if (matcher.matches()) {
            return sanitizer.apply(matcher.group(1)) + "@" + sanitizer.apply(IDN.toUnicode(matcher.group(2)));
        }
        return sanitizer.apply(completeAddress);
    }
}
