# NetNeedle

We believe that hiding a needle in a haystack is easier if the needle looks like hay.

NetNeedle provides for encrypted control channels and chat sessions that are disguised to look like other common network activity. It does not transmit any usable data in the “payload” sections of any packet, so forensic analysts will only see ICMP ping packets that look identical to ordinary ping or HTTP GET requests. The actual data is encoded in IP headers in fields that typically contain random data.

In addition to evasion features, penetration testers can use this tool to maintain control over servers in environments with highly restrictive access lists. Because it subverts expectations surrounding network traffic, NetNeedle allows users to set up back doors that use simple ICMP packets or TCP ports that are already in use. Administrators who believe that they are safe due to “principle of least privilege” access control lists or who believe that ICMP ping is harmless will find themselves sadly mistaken.

