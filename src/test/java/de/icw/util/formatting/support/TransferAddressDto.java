package de.icw.util.formatting.support;

import java.io.Serializable;

import lombok.Data;

@Data
@SuppressWarnings("javadoc")
public class TransferAddressDto implements Serializable {

	private static final long serialVersionUID = 5329606920285197130L;

    private String streetLine;

    private String otherDesignation;

    private String city;

    private String postalCode;

    private String region;

    private String country;

    private String telecom;
}
