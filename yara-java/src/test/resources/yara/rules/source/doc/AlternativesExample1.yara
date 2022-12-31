/*
There are also situations in which you may want to provide different alternatives
for a given fragment of your hex string. In those situations you can use a syntax
which resembles a regular expression:
*/
rule AlternativesExample1
{
    strings:
        $hex_string = { F4 23 ( 62 B4 | 56 ) 45 }

    condition:
        $hex_string
}
/*
This rule will match any file containing F42362B445 or F4235645.
*/
