package io.cui.tools.net;

import java.net.IDN;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * <p>
 * Utility class to handle IDN email addresses.
 * </p>
 * See
 * <ul>
 * <li>
 * <a href="https://docs.oracle.com/javase/tutorial/i18n/network/idn.html">https://docs.oracle.com/
 * javase/tutorial/i18n/network/idn.html</a></li>
 * <li>
 * <a href="https://de.wikipedia.org/wiki/Internationalisierter_Domainname">https://de.wikipedia.org
 * /wiki/Internationalisierter_Domainname</a></li>
 * <li>
 * <a href="https://en.wikipedia.org/wiki/Internationalized_domain_name">https://en.wikipedia.org/
 * wiki/Internationalized_domain_name</a></li>
 * </ul>
 *
 * @author Matthias Walliczek
 */
@UtilityClass
public class IDNInternetAddress {

    private static final Pattern addressPatternWithDisplayName =
        Pattern.compile("(.{0,64})<(.{1,64})@(.{1,64})>(.{0,64})");

    private static final Pattern addressPattern = Pattern.compile("(.{1,64})@(.{1,64})");

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
     * Encodes the given address and sanitizes the elements with the provided sanitizer. It takes
     * care on the special elements like {@code <>} by not trying to sanitize them.
     *
     * @param completeAddress
     * @param sanitizer to be passed as UnaryOperator
     * @return the sanitized and encoded address.
     */
    public static String encode(@NonNull final String completeAddress, UnaryOperator<String> sanitizer) {
        var matcher = addressPatternWithDisplayName.matcher(completeAddress);
        if (matcher.matches() && matcher.groupCount() == 4) {
            return sanitizer.apply(matcher.group(1)) + "<" + sanitizer.apply(matcher.group(2)) + "@" + sanitizer
                    .apply(IDN.toASCII(matcher.group(3))) + ">" + sanitizer.apply(matcher.group(4));
        }
        matcher = addressPattern.matcher(completeAddress);
        if (matcher.matches() && matcher.groupCount() == 2) {
            return sanitizer.apply(matcher.group(1)) + "@" + sanitizer.apply(IDN.toASCII(matcher.group(2)));
        }
        return sanitizer.apply(completeAddress);
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
     * Decodes the given address and sanitizes the elements with the provided sanitizer. It takes
     * care on the special elements like <> by not trying to sanitize them.
     *
     * @param completeAddress
     * @param sanitizer to be passed as UnaryOperator
     * @return the sanitized and decoded address.
     */
    public static String decode(@NonNull final String completeAddress, UnaryOperator<String> sanitizer) {
        var matcher = addressPatternWithDisplayName.matcher(completeAddress);
        if (matcher.matches() && matcher.groupCount() == 4) {
            return sanitizer.apply(matcher.group(1)) + "<" + sanitizer.apply(matcher.group(2)) + "@" + sanitizer
                    .apply(IDN.toUnicode(matcher.group(3))) + ">" + sanitizer.apply(matcher.group(4));
        }
        matcher = addressPattern.matcher(completeAddress);
        if (matcher.matches() && matcher.groupCount() == 2) {
            return sanitizer.apply(matcher.group(1)) + "@" + sanitizer.apply(IDN.toUnicode(matcher.group(2)));
        }
        return sanitizer.apply(completeAddress);
    }
}
