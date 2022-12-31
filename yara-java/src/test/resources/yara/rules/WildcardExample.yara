/*
Strings
There are three types of strings in YARA: hexadecimal strings,
text strings and regular expressions. Hexadecimal strings are
used for defining raw sequences of bytes, while text strings
and regular expressions are useful for defining portions of
legible text. However text strings and regular expressions can
be also used for representing raw bytes by mean of escape
sequences as will be shown below.

Hexadecimal strings
Hexadecimal strings allow three special constructions that make
them more flexible: wild-cards, jumps, and alternatives.
Wild-cards are just placeholders that you can put into the string
indicating that some bytes are unknown and they should match anything.
The placeholder character is the question mark (?). Here you have an
example of a hexadecimal string with wild-cards:
*/
rule WildcardExample
{
    strings:
        $hex_string = { E2 34 ?? C8 A? FB }

    condition:
        $hex_string
}
/*
As shown in the example the wild-cards are nibble-wise, which means
that you can define just one nibble of the byte and leave the other unknown.
*/
