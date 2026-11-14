import pytest
from app.validators import (ValidationError, validate_username, validate_email,
                            validate_password, validate_note)

PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "admin' /* x */",
    "' UNION SELECT username,password FROM users--",
    "1' AND SLEEP(5)--",
    "1; DROP TABLE users",
    "x'; INSERT INTO users VALUES (1,2,3);--",
    "1 OR 1=1",
    "BENCHMARK(100000,MD5('a'))",
]


@pytest.mark.parametrize("p", PAYLOADS)
def test_payloads_rejected_everywhere(p):
    for fn in (validate_username, validate_note):
        with pytest.raises(ValidationError):
            fn(p)
    with pytest.raises(ValidationError):
        validate_email(p + "@x.com")


def test_good_values_pass():
    assert validate_username("akram_01") == "akram_01"
    assert validate_email("Akram@Mail.com") == "akram@mail.com"
    assert validate_note("Meeting at 5 pm, bring laptop!") == "Meeting at 5 pm, bring laptop!"
    assert validate_password("Passw0rd123") == "Passw0rd123"


@pytest.mark.parametrize("bad", ["ab", "a" * 31, "has space", "semi;colon", 123, None])
def test_bad_usernames(bad):
    with pytest.raises(ValidationError):
        validate_username(bad)


@pytest.mark.parametrize("bad", ["short1", "onlyletters", "12345678", "a1" * 40])
def test_bad_passwords(bad):
    with pytest.raises(ValidationError):
        validate_password(bad)


def test_note_length():
    with pytest.raises(ValidationError):
        validate_note("a" * 501)
    with pytest.raises(ValidationError):
        validate_note("   ")