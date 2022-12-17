package io.cui.util.formatting.support;

import java.io.Serializable;

import lombok.Data;

@SuppressWarnings("javadoc")
@Data
public class AddressDto implements Serializable {

    private static final long serialVersionUID = -8011318084675794828L;
    private String streetAddressLine;
    private String postalCode;
    private String city;
    private String country;
    private String state;
    private String organization;
    private String line1;
    private String line2;
    private String flat;
    private String corpus;
    private String zipCodeExtension;
}
