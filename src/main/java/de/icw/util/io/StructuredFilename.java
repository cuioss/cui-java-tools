package de.icw.util.io;

import java.io.File;
import java.io.Serializable;
import java.nio.file.Path;
import java.util.List;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

/**
 * Helper class for splitting / interacting with Filename and corresponding suffixes.
 *
 * @author Oliver Wolff
 */
@EqualsAndHashCode
@ToString
public class StructuredFilename implements Serializable {

    private static final long serialVersionUID = 7473756881958645393L;

    @Getter
    private final String originalName;

    @Getter
    private final String namePart;

    @Getter
    private final String suffix;

    /**
     * Constructor.
     *
     * @param filename to be checked
     */
    @SuppressWarnings("squid:S1871") // owolff: Although duplicate code for case 0 and case 1 I find
                                     // it better readable
    public StructuredFilename(final String filename) {
        originalName = filename;
        final List<String> list =
            Lists.newArrayList(Splitter.on(".").omitEmptyStrings().split(filename));
        switch (list.size()) {
            case 0:
                namePart = filename;
                suffix = null;
                break;
            case 1:
                namePart = filename;
                suffix = null;
                break;
            case 2:
                namePart = list.get(0);
                suffix = list.get(1);
                break;
            default:
                suffix = list.get(list.size() - 1);
                namePart = Joiner.on('.').join(list.subList(0, list.size() - 1));
                break;
        }
    }

    /**
     * Constructor
     *
     * @param path to be used as source, must not be null
     */
    public StructuredFilename(final Path path) {
        this(path.getName(path.getNameCount() - 1).toString());
    }

    /**
     * Constructor
     *
     * @param file to be used as source, must not be null
     */
    public StructuredFilename(final File file) {
        this(file.toPath());
    }

    /**
     * @param nameSuffix to be used for appending the name part. may be null
     * @return the created name string. if namePart = "namePart", nameSuffix=".nameSuffix" and
     *         suffix = "suffix" the resulting String will be "namePart.nameSuffix.suffix"
     */
    public String getAppendedName(final String nameSuffix) {
        final StringBuilder builder = new StringBuilder(namePart);
        if (null != nameSuffix) {
            builder.append(nameSuffix);
        }
        if (null != suffix) {
            builder.append('.');
            builder.append(suffix);
        }
        return builder.toString();
    }
}
