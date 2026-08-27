# Security Score

Atlhas1x starts its internal Security Score at 100 and reduces it for distinct findings according to severity:

| Severity | Score impact |
| --- | ---: |
| INFO | 0 |
| LOW | -2 |
| MEDIUM | -5 |
| HIGH | -10 |
| CRITICAL | -20 |

The score is bounded between 0 and 100. Findings that are `UNKNOWN`, `NOT AVAILABLE`, `NOT APPLICABLE`, or `ACCESS DENIED` do not reduce it. The scanner also avoids applying the same score impact twice for the same underlying finding.

The overall risk level is calculated from the highest supported finding severity, not directly from the numeric score.

This is an Atlhas1x project metric, not an official Microsoft, CIS, NIST, or industry-standard security score. It supports review; it does not replace a security assessment or certify a system.
