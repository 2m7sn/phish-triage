from phish_triage.rules import check_domain, edit_distance, fold


def codes(host):
    return {f.code for f in check_domain(host)}


def test_real_brand_domains_are_not_flagged():
    for h in ("absher.sa", "login.absher.sa", "alrajhibank.com.sa", "www.my.gov.sa", "spl.com.sa", "mail.corp.example"):
        assert codes(h) == set(), h


def test_typo_and_brand_term():
    assert edit_distance("alrajhlbank", "alrajhibank") == 1
    assert "DOMAIN_LOOKALIKE" in codes("alrajhlbank.example")
    assert "DOMAIN_BRAND_TERM" in codes("alrajhi-secure.example")
    assert "DOMAIN_BRAND_SUBDOMAIN" in codes("spl.com.sa.track-parcel.example")
    assert "DOMAIN_BRAND_SUBDOMAIN" in codes("login.corp.example.docs-share.example")


def test_cyrillic_idn_and_digit_substitution():
    c = codes("xn--bsher-3ve.example")  # Cyrillic а + bsher
    assert {"URL_IDN", "DOMAIN_HOMOGLYPH"} <= c
    assert "DOMAIN_HOMOGLYPH" in codes("c0rp.example")


def test_arabic_homoglyph_and_arabic_brand_name():
    # Arabic alef (U+0627) in place of Latin l: aاrajhibank, raw punycode (bidi-invalid, so no idna codec)
    assert fold("aاrajhibank") == "alrajhibank"
    assert "DOMAIN_HOMOGLYPH" in codes("xn--arajhibank-28m.example")
    # brand written in Arabic script: أبشر
    assert "DOMAIN_HOMOGLYPH" in codes("xn--igbk1al.example")
