/*
You can add comments to your YARA rules just as if it was a C source file,
both single-line and multi-line C-style comments are supported.
*/
/*
    This is a multi-line comment ...
*/
rule CommentExample   // ... and this is single-line comment
{
    condition:
        false  // just a dummy rule, don't do this
}
