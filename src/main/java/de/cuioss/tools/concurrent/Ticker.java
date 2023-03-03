package de.cuioss.tools.concurrent;

import java.io.Serializable;

/**
 * A time source; returns a time value representing the number of nanoseconds elapsed since some
 * fixed but arbitrary point in time. Note that most users should use {@link StopWatch} instead of
 * interacting with this class directly.
 *
 * <p>
 * <b>Warning:</b> this type can only be used to measure elapsed time, not wall time.
 *
 * @author com.google.common.base.Ticker
 */
public class Ticker implements Serializable {

    private static final long serialVersionUID = -1361587646696392654L;

    /** @return the number of nanoseconds elapsed since this ticker's fixed point of reference. */
    public long read() {
        return System.nanoTime();
    }
}
