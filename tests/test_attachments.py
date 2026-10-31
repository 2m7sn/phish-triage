from phish_triage.parse import Attachment
from phish_triage.rules import OLE_MAGIC, check_attachments


def codes(name, data=b"x", body=""):
    return {f.code for f in check_attachments([Attachment(name, data)], body)}


def test_attachment_rules():
    assert codes("Invoice.pdf.exe") == {"ATT_DOUBLE_EXT"}
    assert codes("Scan.pdf.lnk") == {"ATT_DOUBLE_EXT"}
    assert codes("PO.iso") == {"ATT_DANGEROUS_TYPE"}
    assert codes("notes.one") == {"ATT_DANGEROUS_TYPE"}
    assert codes("Payslip.html") == {"ATT_HTML"}
    assert codes("Bonus.xlsm") == {"ATT_MACRO"}
    assert codes("Payslip.doc", OLE_MAGIC + b"\x00" * 8) == {"ATT_OLE_LEGACY"}
    assert codes("Payslip.doc", b"not ole") == set()
    assert codes("x.zip") == {"ATT_ARCHIVE"}
    assert codes("x.zip", body="archive password: 2026") == {"ATT_ARCHIVE_PASSWORD"}
    assert codes("report.pdf", b"%PDF-1.4") == set()
    assert codes("invite.ics") == set()
