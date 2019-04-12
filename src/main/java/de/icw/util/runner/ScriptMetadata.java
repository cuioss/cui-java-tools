package de.icw.util.runner;

import java.io.Serializable;

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * A metadata object providing all necessary paths for {@link ShellScriptRunner}
 *
 * @author Oliver Wolff
 */
@Builder
@Value
public class ScriptMetadata implements Serializable {

    private static final long serialVersionUID = -1377795090788123793L;

    /** Default time to wait whether the shutdown was successful in seconds: 60. */
    public static final int SHUTDOWN_TIMEOUT = 60;

    /**
     * Default number of attempts to check whether the startup has succeeded, see
     * {@value #STARTED_CHECK_INTERVAL}: 10.
     */
    public static final int MAX_ATTEMPTS_STARTED_CHECK = 10;

    /**
     * Default time to wait whether the startup was successful in seconds: 5
     */
    public static final int STARTED_CHECK_INTERVAL = 5;

    /** Defines the name of the script, to be used for logging. */
    @NonNull
    private String name;

    /** Tells the used ProcessBuilder to redirect the errorStream to the default outputStream. */
    @Builder.Default
    private boolean redirectOutputStream = true;

    private ScriptMetadataParameter linuxParameter;

    private ScriptMetadataParameter windowsParameter;

    /** See {@link #SHUTDOWN_TIMEOUT}. */
    @Builder.Default
    private int shutdownTimeout = SHUTDOWN_TIMEOUT;

    /** See {@link #MAX_ATTEMPTS_STARTED_CHECK}. */
    @Builder.Default
    private int startCheckCount = MAX_ATTEMPTS_STARTED_CHECK;

    /** See {@link #STARTED_CHECK_INTERVAL}. */
    @Builder.Default
    private long startCheckTimeout = STARTED_CHECK_INTERVAL;
}
