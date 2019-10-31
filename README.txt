# Project2: DNS query/response
# Authors: Zach Morgan, Arthur Heiles
# Language: Python


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

### Challenges

