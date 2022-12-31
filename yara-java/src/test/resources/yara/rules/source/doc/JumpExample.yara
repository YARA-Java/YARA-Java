/*
Wild-cards are useful when defining strings whose content can vary
but you know the length of the variable chunks, however, this is not
always the case. In some circumstances you may need to define strings
with chunks of variable content and length.
In those situations you can use jumps instead of wild-cards:
*/
rule JumpExample
{
    strings:
        $hex_string = { F4 23 [4-6] 62 B4 }

    condition:
        $hex_string
}
/*
In the example above we have a pair of numbers enclosed in square brackets
and separated by a hyphen, that's a jump. This jump is indicating that any
arbitrary sequence from 4 to 6 bytes can occupy the position of the jump.

Any jump [X-Y] must meet the condition 0 <= X <= Y. In previous versions of
YARA both X and Y must be lower than 256, but starting with YARA 2.0 there
is no limit for X and Y.
*/
