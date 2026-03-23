from gcp_key_auditor.scanner import extract_keys_from_text


def test_extract_keys_from_text_deduplicates() -> None:
    key = "AIza" + "A" * 35
    text = f"x {key} y {key}"
    got = extract_keys_from_text(text)
    assert got == [key]
