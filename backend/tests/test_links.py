from links import domain_in_text, extract_links, host_of


def test_extract_links_text_and_entities():
    html = '<p>Hi</p><a href="https://x.com/a?b=1&amp;c=2">Click <b>here</b></a>'
    assert extract_links(html) == [("https://x.com/a?b=1&c=2", "Click here")]


def test_host_of():
    assert host_of("https://Mail.PayPal.com:443/x") == "mail.paypal.com"
    assert host_of("https://paypal.com@evil.ru/login") == "evil.ru"  # the "@" trick
    assert host_of("mailto:a@b.com") == ""
    assert host_of("javascript:alert(1)") == ""


def test_domain_in_text():
    assert domain_in_text("www.chase.com") == "chase.com"
    assert domain_in_text("https://chase.com/login") == "chase.com"
    assert domain_in_text("Click here") == ""
    assert domain_in_text("invoice.pdf") == ""
