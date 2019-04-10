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
    WINDOWS,

    /** MacOsx. */
    MAC_OS;

    /**
     * @return the {@link Environment} determined from the system-property
     */
    static Environment determineEnviromnent() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            return WINDOWS;
        }
        if (os.contains("mac os x")) {
            return MAC_OS;
        }
        return Environment.LINUX;
    }
}
