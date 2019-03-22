package de.icw.util.formatting.support;

import java.io.Serializable;

import lombok.Data;

@Data
@SuppressWarnings("javadoc")
public class PersonDto implements Serializable {

	private static final long serialVersionUID = 8774114732577448146L;

	private String familyNamePrefix;

	private String familyName;

	private String familyBirthname;

	private String givenName;

	private String givenNameSuffix;

	private String givenBirthname;

	private String middleName;

	private String nickname;

	private String academicPrefix;

	private String academicSuffix;

	private String professionalPrefix;

	private String professionalSuffix;

	private String genericPrefix;

	private String genericSuffix;

	private String nobilityPrefix;

	private String nobilitySuffix;

	private String gender;

}
