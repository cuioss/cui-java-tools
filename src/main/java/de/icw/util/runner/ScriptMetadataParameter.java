package de.icw.util.runner;

import static com.google.common.base.Strings.emptyToNull;
import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.base.Strings.nullToEmpty;

import java.io.Serializable;
import java.util.Optional;

import com.google.common.base.Joiner;

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * A metadata object providing all necessary paths for {@link ShellScriptRunner}, usually provided
 * via {@link ScriptMetadata}
 *
 * @author Oliver Wolff
 *
 */
@Builder
@Value
public class ScriptMetadataParameter implements Serializable {

    private static final long serialVersionUID = 4656725288270492851L;

    /** Defines the system this parameter can be applied to. */
    @NonNull
    private Environment environment;

    /** Identifies the start script: Must be set */
    @NonNull
    private String startScript;

    /** Identifies the parameters passed to the start script. */
    private String startParameter;

    /** Optional stop script. */
    private String stopScript;

    /** Identifies the parameters passed to the optional stop script, therefore optional as well. */
    private String stopParameter;

    /**
     * @return a String representation of {@link #getStartScript()} concatenated with
     *         {@link #getStartParameter()} if present.
     */
    public String getStartScriptWithParameter() {
        return Joiner.on(' ').skipNulls().join(nullToEmpty(getStartScript()), emptyToNull(getStartParameter()));
    }

    /**
     * @return a String representation of {@link #getStopScript()} concatenated with
     *         {@link #getStopParameter()} if present.
     */
    public Optional<String> getStopScriptWithParameter() {
        if (isNullOrEmpty(getStopScript())) {
            return Optional.empty();

        }
        return Optional
                .of(Joiner.on(' ').skipNulls().join(nullToEmpty(getStopScript()), emptyToNull(getStopParameter())));
    }
}
