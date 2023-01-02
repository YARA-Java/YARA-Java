/*
YARA rules are easy to write and understand, and they have a syntax that resembles the C language.
Here is the simplest rule that you can write for YARA, which does absolutely nothing:
*/
rule DummyExample
{
    condition:
        false
}
/*
Each rule in YARA starts with the keyword rule followed by a rule identifier.
Identifiers must follow the same lexical conventions of the C programming language,
they can contain any alphanumeric character and the underscore character, but the first character
cannot be a digit. Rule identifiers are case sensitive and cannot exceed 128 characters.
*/
