package de.icw.util.runner;

import java.io.Serializable;
import java.util.List;

import lombok.Builder;
import lombok.NonNull;
import lombok.Singular;
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
    @Singular
    private List<String> startParameters;

    /** Optional stop script. */
    private String stopScript;

    /** Identifies the parameters passed to the optional stop script, therefore optional as well. */
    @Singular
    private List<String> stopParameters;

}
