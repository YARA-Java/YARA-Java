/*
Text strings
As shown in previous sections, text strings are generally defined like this:
*/
rule TextExample
{
    strings:
        $text_string = "foobar"

    condition:
        $text_string
}
/*
This is the simplest case: an ASCII-encoded, case-sensitive string.
However, text strings can be accompanied by some useful modifiers that alter
the way in which the string will be interpreted. Those modifiers are appended
at the end of the string definition separated by spaces, as will be discussed below.
*/
