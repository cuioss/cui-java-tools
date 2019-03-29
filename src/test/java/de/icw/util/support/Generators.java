package de.icw.util.support;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Provides a number of simple generators for unit-tests
 *
 * @author Oliver Wolff
 *
 */
public class Generators {

    /**
     * @param count
     * @return a {@link List} containing a number random String derived by {@link UUID}
     */
    public static List<String> randomStrings(int count) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            result.add(randomString());
        }
        return result;
    }

    /**
     * @return a {@link List} containing a number random String derived by {@link UUID}
     */
    public static String randomString() {
        return UUID.randomUUID().toString();
    }

    /**
     * @param lowerBound
     * @param upperBound
     * @return a pseudo random number in between the given boundaries
     */
    public static int randomInt(int lowerBound, int upperBound) {
        checkArgument(upperBound > lowerBound, "UpperBound must be larger than lower bound");
        return ThreadLocalRandom.current().nextInt(lowerBound, upperBound + 1);
    }

}
