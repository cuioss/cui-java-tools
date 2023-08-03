package de.cuioss.tools.string;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.lang.Boolean.valueOf;
import static java.lang.Integer.valueOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class TextSplitterTest {

    private static final String TEXT_WITH_ENFORCED_LINEBREAKS_IS_WRONG = "Text with enforced linebreaks is wrong.";

    private static final String ABRIDGED_TEXT_IS_WRONG = "Abridged text is wrong.";

    private static final String INV_SPACE = "\u200B";

    private TextSplitter textSplitter;

    @Test
    void shouldRecognizeIfNoAbridgeNeededAtAll() {
        assertEquals("", new TextSplitter(null).getAbridgedText(), ABRIDGED_TEXT_IS_WRONG);

        assertEquals("", new TextSplitter(null).getTextWithEnforcedLineBreaks(),
                TEXT_WITH_ENFORCED_LINEBREAKS_IS_WRONG);

        assertEquals("", new TextSplitter("").getAbridgedText(), ABRIDGED_TEXT_IS_WRONG);

        assertThat(valueOf(new TextSplitter("").isAbridged()), is(FALSE));

        assertEquals("", new TextSplitter("").getTextWithEnforcedLineBreaks(), TEXT_WITH_ENFORCED_LINEBREAKS_IS_WRONG);
    }

    @Test
    void shouldAbridgeHumanProducedText() {
        final var text = "My extremly long text with some usefull information";
        textSplitter = new TextSplitter(text);
        textSplitter.setAbridgedLength(valueOf(16));

        assertEquals("My extremly ...", textSplitter.getAbridgedText(), ABRIDGED_TEXT_IS_WRONG);
        assertThat(valueOf(textSplitter.isAbridged()), is(TRUE));
    }

    @Test
    void shouldRecognizeIfNoAbridgeToHumanProducedTextNeeded() {
        final var text = "My short text";
        textSplitter = new TextSplitter(text);

        assertEquals(text, textSplitter.getAbridgedText(), ABRIDGED_TEXT_IS_WRONG);
        assertThat(valueOf(textSplitter.isAbridged()), is(FALSE));
    }

    @Test
    void shouldAbridgeComputerProducedText() {
        final var text = "Myextremlylongtextwithsomeusefullinformation";
        textSplitter = new TextSplitter(text);
        textSplitter.setAbridgedLength(valueOf(16));

        assertEquals("Myextremlylo ...", textSplitter.getAbridgedText(), ABRIDGED_TEXT_IS_WRONG);
        assertThat(valueOf(textSplitter.isAbridged()), is(TRUE));
    }

    @Test
    void shouldRecognizeIfNoAbridgeToComputerProducedNeeded() {
        final var text = "Myshorttext";
        textSplitter = new TextSplitter(text);

        assertEquals(text, textSplitter.getAbridgedText(), ABRIDGED_TEXT_IS_WRONG);
        assertThat(valueOf(textSplitter.isAbridged()), is(FALSE));
    }

    @Test
    void shouldProvideWebConformLongText() {
        final var text = "My-extremly.long;text_with!some usefull:information?andAveryLongDivulgementWithVeryLongComments";

        final var expected = "My-" + INV_SPACE + "extremly." + INV_SPACE + "long;" + INV_SPACE + "text_" + INV_SPACE
                + "with!" + INV_SPACE + "some usefull:" + INV_SPACE + "information?" + INV_SPACE + "andAveryLongDiv"
                + INV_SPACE + "ulgementWithVer" + INV_SPACE + "yLongComments";

        textSplitter = new TextSplitter(text);
        textSplitter.setForceLengthBreak(valueOf(15));

        assertEquals(expected, textSplitter.getTextWithEnforcedLineBreaks(), TEXT_WITH_ENFORCED_LINEBREAKS_IS_WRONG);
    }

    @Test
    void shouldProvideTextRepresentationForComputerCreatedTextSequence() {
        final var text = "shouldProvideTextRepresentationForComputerCreatedTextSequence";
        textSplitter = new TextSplitter(text);
        assertEquals("shouldProvideTex ...", textSplitter.getAbridgedText(), ABRIDGED_TEXT_IS_WRONG);
        assertEquals(
                "shouldProvideTe" + INV_SPACE + "xtRepresentatio" + INV_SPACE + "nForComputerCre" + INV_SPACE
                        + "atedTextSequenc" + INV_SPACE + "e",
                textSplitter.getTextWithEnforcedLineBreaks(), "Text with enforced linebreaks is wrong. ");
    }
}
