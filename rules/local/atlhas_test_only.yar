/* TEST ONLY: benign fixture for validating local yara-python integration. */
rule ATL_Test_Only_Benign_Marker
{
    meta:
        author = "Atlhas1x"
        description = "Matches only the benign Atlhas1x test marker"
        purpose = "TEST ONLY"
    strings:
        $marker = "ATLHAS1X_YARA_TEST_MARKER"
    condition:
        $marker
}

/* TEST ONLY: generic, low-confidence fixture. It does not identify malware. */
rule ATL_Test_Generic_Marker
{
    meta:
        author = "Atlhas1x"
        description = "Generic benign test marker"
        purpose = "TEST ONLY"
    strings:
        $marker = "ATLHAS1X_YARA_GENERIC_MARKER"
    condition:
        $marker
}

/* TEST ONLY: high-confidence classification fixture, not a malware rule. */
rule ATL_Test_HighConfidence_Marker
{
    meta:
        author = "Atlhas1x"
        description = "High-confidence benign test marker"
        purpose = "TEST ONLY"
        confidence = "high"
    strings:
        $marker = "ATLHAS1X_YARA_HIGHCONF_MARKER"
    condition:
        $marker
}
