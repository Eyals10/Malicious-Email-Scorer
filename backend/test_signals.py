from signals import check_auth

GMAIL = "mx.google.com;\r\n       "


def points(signals):
    return sum(s.points for s in signals)


def test_all_pass_gives_nothing():
    assert check_auth(GMAIL + "dkim=pass header.i=@paypal.com; spf=pass; dmarc=pass") == []


def test_spf_fail():
    assert points(check_auth(GMAIL + "dkim=pass; spf=fail; dmarc=pass")) == 15


def test_spf_softfail_is_weaker_than_fail():
    assert points(check_auth(GMAIL + "dkim=pass; spf=softfail; dmarc=pass")) == 5


def test_dkim_missing():
    assert points(check_auth(GMAIL + "spf=pass; dmarc=pass")) == 10


def test_one_good_dkim_signature_is_enough():
    assert check_auth(GMAIL + "dkim=fail; dkim=pass; spf=pass; dmarc=pass") == []


def test_everything_fails():
    assert points(check_auth(GMAIL + "dkim=fail; spf=fail; dmarc=fail")) == 45  # capped later, in scoring


def test_fake_header_not_from_gmail_is_ignored():
    assert check_auth("evil.com; dkim=fail; spf=fail; dmarc=fail") == []


def test_missing_header_adds_nothing():
    assert check_auth("") == []
