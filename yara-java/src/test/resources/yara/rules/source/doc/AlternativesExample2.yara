/*
But more than two alternatives can be also expressed.In fact, there are no limits
to the amount of alternative sequences you can provide, and neither to their lengths.
*/
rule AlternativesExample2
{
    strings:
        $hex_string = { F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }

    condition:
        $hex_string
}
/*
As can be seen also in the above example, strings containing wild-cards are allowed
as part of alternative sequences.
*/
