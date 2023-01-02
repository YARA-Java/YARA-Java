/*
Rules are generally composed of two sections: strings definition and condition.
The strings definition section can be omitted if the rule doesn't rely on any string,
but the condition section is always required. The strings definition section is where
the strings that will be part of the rule are defined. Each string has an identifier
consisting of a $ character followed by a sequence of alphanumeric characters and underscores,
these identifiers can be used in the condition section to refer to the corresponding string.
Strings can be defined in text or hexadecimal form, as shown in the following example:
*/
rule ExampleRule
{
    strings:
        $my_text_string = "text here"
        $my_hex_string = { E2 34 A1 C8 23 FB }

    condition:
        $my_text_string or $my_hex_string
}
/*
Text strings are enclosed in double quotes just like in the C language.
Hex strings are enclosed by curly brackets, and they are composed by a sequence of hexadecimal numbers
that can appear contiguously or separated by spaces. Decimal numbers are not allowed in hex strings.

The condition section is where the logic of the rule resides. This section must contain a boolean
expression telling under which circumstances a file or process satisfies the rule or not.
Generally, the condition will refer to previously defined strings by using their identifiers.
In this context the string identifier acts as a boolean variable which evaluate to true if the string
was found in the file or process memory, or false if otherwise.
*/
