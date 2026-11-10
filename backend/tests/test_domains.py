from domains import decode_punycode, domain_of, edit_distance, registrable_domain


def test_domain_of():
    assert domain_of('"PayPal" <x@Mail.PayPal.com>') == "mail.paypal.com"
    assert domain_of("no address here") == ""


def test_registrable_domain():
    assert registrable_domain("mail.paypal.com") == "paypal.com"
    assert registrable_domain("secure.leumi.co.il") == "leumi.co.il"


def test_punycode_reveals_foreign_letters():
    assert decode_punycode("xn--pple-43d.com") == "аpple.com"  # Cyrillic 'а'


def test_edit_distance():
    assert edit_distance("paypal", "paypal") == 0
    assert edit_distance("paypall", "paypal") == 1
    assert edit_distance("amazom", "amazon") == 1
    assert edit_distance("microsfot", "microsoft") == 1  # swapped neighbours count once
    assert edit_distance("telegraph", "telegram") == 2
