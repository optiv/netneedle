# NetNeedle

We believe that hiding a needle in a haystack is easier if the needle looks like hay.

NetNeedle provides for encrypted control channels and chat sessions that are disguised to look like other common network activity. It only transmits "decoy" data in the “payload” section of any packet, so forensic analysts will only see packets that look identical to ordinary ping or HTTP GET requests. The actual data is encoded in IP headers in fields that typically contain random values.

In addition to evasion features, penetration testers can use this tool to maintain control over servers in environments with highly restrictive access lists. Because NetNeedle subverts expectations surrounding network traffic, it enables users to set up back doors that use simple ICMP packets or TCP ports that are already in use. Administrators who believe that they are safe due to “principle of least privilege” access control lists or who believe that ICMP ping is harmless will find themselves sadly mistaken.

