# Zone file format

A zone file is a text file containing a textual representation of RAINS entries.
Typically, a zone file describes all entries of a zone. But it can also be used
to pre-load entries at startup of a caching server or a cache to output the
currently stored entries. It is RAINS analog to DNS's zone file format defined
in section 5 of [2], used by BIND [3] and many more.

## Format

A zone file contains an entry or a sequence of entries. An entry typically
starts on a new line. Each entry consists of several items depending on the type
as specified below. At least one white space (space, tab, return) act as a
delimiter between items. A comment starts with a ";" (semicolon) which results
in the rest of the line being ignored by the parser. Empty lines are allowed
anywhere in the file, with or without comments.

An entry is either a zone, a shard or an assertion. Parentheses "()" and
brackets "[]" are part of the syntax. Similar to regex we use the following
special characters which are not part of the syntax. Each final non-static term
is a string representation of the type specified in the rains data model. (TODO
CFE should we specify the string representation per type? e.g. public key in
hexadecimal while port in decimal etc.)

- '<>' to group terms (as parenthesis are part of the syntax)
- '|' either term on the left or term on the right (not both)
- '\*' arbitrary number of occurrences of the previous term (including none)
- '\+' at least one occurrence of the previous term

- Zone: :Z: 

### Special encodings

- ';' represents the beginning of a comment. Remainder of the line is ignored.

## Implementation

- readLineFunction: reads next line, separates line by comment delimiter,
  returns scanner to the content part or false if end of line
- parseFunction: takes a scanner as input which splits on white spaces. If the
  scanner is at the end, invoke readLineFunction() to override scanner and
  continue parsing. If no new entries and last entry parsed correctly, return
  content else error.

## Example

An zone file example for the domain example.com.

:Z: example com. [  
    :S: < > [  
            :A: bar  [ :ip4: 192.0.2.0 ]  
            :A: baz  [ :ip4: 192.0.2.1 ]  
            :A: foo [  
                    :ip6:      2001:db8::  
                    :ip4:      192.0.2.2  
            ]  
    ]  
    :S: bar foo [  
            :A: baz  [ :ip4: 192.0.2.1 ] (TODO CFE add sig meta data)  
    ] (TODO CFE add sig meta data)  
]  

## Bibliography
[1] DNS zone file https://en.wikipedia.org/wiki/Zone_file
[2] DNS zone file format, Section 5 https://tools.ietf.org/html/rfc1035
[3] BIND https://www.isc.org/downloads/bind/