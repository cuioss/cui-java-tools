package de.icw.util.runner;

import static de.icw.util.runner.ScriptMetadataParameterTest.LINUX_META;
import static de.icw.util.runner.ScriptMetadataParameterTest.WINDOWS_META;

import org.junit.jupiter.api.Test;

import de.icw.util.support.ObjectMethodsAsserts;

class ScriptMetadataTest {

    static final ScriptMetadata SCRIPT_METADATA =
        ScriptMetadata.builder().linuxParameter(LINUX_META).name("test-script")
                .windowsParameter(WINDOWS_META).macOsParameter(LINUX_META).build();

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(SCRIPT_METADATA);
    }
}
