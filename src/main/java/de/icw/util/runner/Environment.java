package de.icw.util.runner;

/**
 * Represents the concrete environment / OS the script will be executed
 *
 * @author Oliver Wolff
 *
 */
enum Environment {

    /** Undefined Linux distribution. */
    LINUX,

    /** Windows. */
    WINDOWS;

    /**
     * @return the {@link Environment} determined from the system-property
     */
    static Environment determineEnviromnent() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            return WINDOWS;
        }
        return Environment.LINUX;
    }
}
