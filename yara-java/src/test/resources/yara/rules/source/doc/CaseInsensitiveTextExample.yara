/*
Case-insensitive strings
Text strings in YARA are case-sensitive by default, however you can turn
your string into case-insensitive mode by appending the modifier nocase
at the end of the string definition, in the same line:
*/
rule CaseInsensitiveTextExample
{
    strings:
        $text_string = "foobar" nocase

    condition:
        $text_string
}
/*
With the nocase modifier the string foobar will match Foobar, FOOBAR, and fOoBaR.
This modifier can be used in conjunction with any modifier, except base64 and base64wide.
*/
