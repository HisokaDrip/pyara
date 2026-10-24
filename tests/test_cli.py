import json
import sys
from pathlib import Path

import pytest

from pyara.cli import main

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "examples" / "rules"
sys.path.insert(0, str(ROOT / "examples"))
import make_samples  # noqa: E402


@pytest.fixture(scope="module")
def samples(tmp_path_factory):
    out = tmp_path_factory.mktemp("samples")
    make_samples.main(str(out))
    return out


def test_example_rules_catch_every_sample(samples, capsys):
    assert main(["-r", str(RULES), str(samples)]) == 0
    lines = capsys.readouterr().out.splitlines()
    found = {line.split()[0]: Path(line.split()[-1]).name for line in lines}
    assert found == {
        "AWS_Access_Key_ID": "settings.env",
        "Private_Key_Block": "id_rsa_backup",
        "PowerShell_Download_Cradle": "deploy.ps1",
        "EICAR_Test_File": "eicar.com",
        "PE_Executable": "fake_app.exe",
        "ELF_Binary": "fake_lib.so",
        "High_Entropy_Blob": "vault.bin",
    }


def test_benign_files_stay_quiet(samples, capsys):
    project = samples / "project"
    assert main([str(RULES), str(project / "notes.md"), str(project / "cleanup.ps1")]) == 0
    assert capsys.readouterr().out == ""


def test_non_recursive_skips_subdirs(samples, capsys):
    main([str(RULES), str(samples)])
    assert "settings.env" not in capsys.readouterr().out


def test_json_output(samples, capsys):
    main(["--json", str(RULES), str(samples / "eicar.com")])
    record = json.loads(capsys.readouterr().out)
    assert record["matches"][0]["rule"] == "EICAR_Test_File"
    assert record["matches"][0]["strings"]["$head"] == [0]


def test_show_strings(samples, capsys):
    main(["-s", str(RULES), str(samples / "project" / "settings.env")])
    assert ":$key: AKIA" in capsys.readouterr().out


def test_fail_on_match(samples):
    assert main(["--fail-on-match", str(RULES), str(samples / "eicar.com")]) == 1
    assert main(["--fail-on-match", str(RULES), str(samples / "project" / "notes.md")]) == 0


def test_max_size_skips_big_files(samples, capsys):
    main(["--max-size", "0.01", str(RULES), str(samples / "vault.bin")])
    assert capsys.readouterr().out == ""


def test_bad_rules_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.yar"
    bad.write_text('rule Broken { strings: $a = "x" condition: $nope }')
    assert main([str(bad), str(tmp_path)]) == 2
    assert "undefined string" in capsys.readouterr().err
