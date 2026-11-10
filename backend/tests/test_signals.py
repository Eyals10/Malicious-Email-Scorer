import pytest

from signals import check_auth, check_identity

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


LOOKALIKES = ["paypa1.com", "micros0ft-support.com", "paypal-secure-login.com", "amazom.com",
              "xn--pple-43d.com", "paypal.verify-account.xyz", "ups-delivery-notice.com",
              "rnicrosoft.com", "g00gle.com", "bankhapoalim-secure.co.il"]

LEGITIMATE = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "ynet.co.il", "walla.co.il",
              "github.com", "mail.paypal.com", "email.apple.com", "groups.google.com",
              "apply.workable.com", "cooking.com", "finance-news.com", "cloudflare.com", "ops-team.com",
              "purchase-orders.com", "team-updates.com", "teamviewer.com", "mycompany.co.il", "university.ac.il"]


@pytest.mark.parametrize("domain", LOOKALIKES)
def test_lookalike_domains_caught(domain):
    assert any(s.points == 30 for s in check_identity(f"x@{domain}", ""))


@pytest.mark.parametrize("domain", LEGITIMATE)
def test_legitimate_domains_not_flagged(domain):
    assert check_identity(f"x@{domain}", "") == []


def test_brand_name_from_free_mail_is_impersonation():
    assert [s.points for s in check_identity('"PayPal Security" <x123@gmail.com>', "")] == [25]
    assert [s.points for s in check_identity('"Microsoft Support" <help@hotmail.com>', "")] == [25]
    assert [s.points for s in check_identity('"Office 365 Admin" <x@gmail.com>', "")] == [25]


@pytest.mark.parametrize("sender", ["x@localhost", "x@.com", '"PayPal" <service@paypal>'])
def test_odd_sender_domain_does_not_crash(sender):
    check_identity(sender, "")  # must not raise; a crash would hide the email from scoring


def test_brand_name_from_real_domain_is_fine():
    assert check_identity('"PayPal" <service@paypal.com>', "") == []


def test_reply_to_different_domain():
    assert [s.points for s in check_identity("ceo@company.com", "ceo.company@outlook.com")] == [15]


def test_reply_to_same_company_is_fine():
    assert check_identity("news@mail.company.com", "support@company.com") == []
