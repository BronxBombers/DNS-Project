# Project2: DNS query/response
# Authors: Zach Morgan, Arthur Heiles
# Language: Python
# Supports MX and NS packets for extra credit


### Approach
    Summary of process:
        - Construct a packet by appending python bytes objects converted from bit strings
        - Send packet to requested server on requested port
        - Wait to receive packets. Timeout after 5 seconds
        - On receipt, parse header for response information. Check for errors
        - Pass data to parser
        - Parser runs on each record:
            - If record is type A, take the IP out of the following data length
            - If record is type CNAME, parse name. Recurse on labels
            - If record is type MX, take out Preference data and parse name.
                Recurse on labels
            - If record is type NS, parse name. Recurse on labels
            Record information is printed as parsed

### Challenges Faced
    Handling of pointers in response domain names - resolved via kinda
        complicated recursion.

    Error checking; insufficient ways to verify bad information - resolved as
        well as possible, but it's hard to tell exactly what went wrong with
        malformed packets

### Features
    - Nicely formatted hex dump
    - Splits records by section
    - Handles MX and NS records

### Tests
    - Various forms of bad command line input
    - The following command line args (produced expected results):
        -ns @8.8.8.8:53 rit.edu
        @8.8.8.8:53 mail.google.com
        -mx @8.8.8.8:53 mail.google.com
        @8.8.8.8:53 google.com
        -mx @8.8.8.8:53 google.com
        @8.8.8.8:53 rit.edu
        @8.8.8.8:53 www.rit.edu
        @8.8.8.8:53 arf
        @8.8.8.8:53 .com
        -mx @8.8.8.8:53 cs.rit.edu
        @8.8.8.8:53 cs.rit.edu
    - manufactured bad packets for (errored as expected):
        altered data within packets
        truncated packets