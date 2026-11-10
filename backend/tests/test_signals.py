import pytest

from links import MAX_HOSTS
from signals import check_auth, check_identity, check_links

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
              "rnicrosoft.com", "g00gle.com", "bankhapoalim-secure.co.il", "microsfot.com", "vvhatsapp.com"]

LEGITIMATE = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "ynet.co.il", "walla.co.il",
              "github.com", "mail.paypal.com", "email.apple.com", "groups.google.com",
              "apply.workable.com", "cooking.com", "finance-news.com", "cloudflare.com", "ops-team.com",
              "purchase-orders.com", "team-updates.com", "teamviewer.com", "mycompany.co.il", "university.ac.il",
              "telegraph.co.uk", "money-transfer.com"]


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


def link(href, text):
    return f'<a href="{href}">{text}</a>'


def link_points(html):
    return sorted((s.points for s in check_links(html)), reverse=True)


def test_link_text_shows_other_site():
    assert link_points(link("https://secure-login.ru/x", "www.chase.com")) == [25]


def test_link_text_matching_destination_is_fine():
    assert link_points(link("https://www.paypal.com/signin", "www.paypal.com")) == []


def test_newsletter_tracking_link_is_fine():
    assert link_points(link("https://u1.ct.sendgrid.net/ls/click?x", "www.ynet.co.il")) == []


def test_link_to_lookalike_domain():
    assert link_points(link("https://paypa1-secure.com/login", "Log in")) == [25]


def test_link_to_raw_ip():
    assert link_points(link("http://185.23.11.4/login", "Log in")) == [20]


def test_punycode_link_is_also_a_lookalike():
    assert link_points(link("https://xn--pple-43d.com", "Apple ID")) == [25, 15]


def test_many_shortened_links_give_one_reason():
    signals = check_links(link("https://bit.ly/a", "a") * 3)
    assert [s.points for s in signals] == [5]
    assert "(and 2 more)" in signals[0].reason


def test_normal_email_links_are_fine():
    html = link("https://github.com/x", "View on GitHub") + link("mailto:a@b.com", "Email us")
    assert link_points(html) == []


def test_too_many_different_websites_is_flagged():
    html = "".join(link(f"https://site{i}.com", "x") for i in range(MAX_HOSTS + 1))
    assert link_points(html) == [15]
