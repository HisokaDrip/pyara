// stuff that should never end up committed

rule AWS_Access_Key_ID : secret cloud
{
    meta:
        description = "AWS access key id (long-term AKIA or temporary ASIA)"
        severity = "high"
    strings:
        $key = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/
    condition:
        $key
}

rule GitHub_Token : secret
{
    meta:
        description = "GitHub personal access / OAuth / app token"
        severity = "high"
    strings:
        $classic = /\bgh[pousr]_[A-Za-z0-9]{36}\b/
        $fine = /\bgithub_pat_[A-Za-z0-9_]{60,}/
    condition:
        any of them
}

rule Private_Key_Block : secret crypto
{
    meta:
        description = "PEM private key"
        severity = "critical"
    strings:
        $begin = /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/
        $end = "PRIVATE KEY-----"
    condition:
        $begin and #end >= 2
}
