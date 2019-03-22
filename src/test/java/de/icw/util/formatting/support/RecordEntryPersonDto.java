package de.icw.util.formatting.support;

import java.io.Serializable;

import lombok.Data;

@Data
@SuppressWarnings("javadoc")
public class RecordEntryPersonDto implements Serializable {

	private static final long serialVersionUID = 1241568817485549262L;

	private String namePrefix;

	private String givenName;

	private String familyName;

	private String nameSuffix;

	private String middleName;

	private String academicTitle;

}
