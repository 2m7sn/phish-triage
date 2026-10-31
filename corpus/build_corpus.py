"""Writes the synthetic .eml corpus and labels.csv next to this file.

Everything here is invented. Links use .example / .invalid and RFC 5737 addresses.
Attachments are dummy bytes with the right magic number only. Re-run: python corpus/build_corpus.py
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
from pathlib import Path

HERE = Path(__file__).parent
BASE = datetime(2026, 10, 20, 9, 14, tzinfo=timezone(timedelta(hours=3)))
TO = "m.alharbi@corp.example"

MZ = b"MZ\x90\x00" + b"\x00" * 60
PK = b"PK\x03\x04" + b"\x00" * 60
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 56
PDF = b"%PDF-1.4\n% dummy\n%%EOF\n"
HTML_ATT = b"<html><body><script>/* harmless placeholder */</script></body></html>"
ZERO = b"\x00" * 64

# Cyrillic 'а' absher, Arabic 'أبشر', Arabic alef replacing the l in alrajhibank. Raw punycode, see rules.decode_label.
CYR_ABSHER = "xn--bsher-3ve.example"
AR_ABSHER = "xn--igbk1al.example"
AR_ALRAJHI = "xn--arajhibank-28m.example"

rows: list[tuple[str, str]] = []
n = 0


def mail(name, label, *, frm, subject, text, html=None, to=TO, reply_to=None, return_path=None,
         spf="pass", dkim="pass", dmarc="pass", auth=True, ip="203.0.113.10", helo=None, attachments=()):
    global n
    n += 1
    addr = frm.split("<")[-1].rstrip(">")
    fdom = addr.split("@")[1]
    rp = return_path or addr
    rpdom = rp.split("@")[1]
    helo = helo or f"mail.{fdom}"
    when = BASE + timedelta(hours=n * 3)
    msg = EmailMessage()
    msg["Return-Path"] = f"<{rp}>"
    msg["Received"] = f"from mx1.corp.example (mx1.corp.example [192.0.2.10]) by mail.corp.example (Postfix) with ESMTPS id 4XK{n:03d}; {format_datetime(when + timedelta(seconds=2))}"
    if auth:
        msg["Authentication-Results"] = (f"mx1.corp.example; spf={spf} smtp.mailfrom={rpdom}; dkim={dkim} header.d={fdom}; "
                                         f"dmarc={dmarc} header.from={fdom}")
        msg["Received-SPF"] = f"{spf.capitalize()} (mx1.corp.example: domain of {rp} {'designates' if spf == 'pass' else 'does not designate'} {ip} as permitted sender) client-ip={ip};"
    msg["Received"] = f"from {helo} ({helo} [{ip}]) by mx1.corp.example (Postfix) with ESMTP id 3AB{n:03d} for <{to}>; {format_datetime(when)}"
    msg["From"] = frm
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = format_datetime(when)
    msg["Message-ID"] = f"<{name}.{n:03d}@{fdom}>"
    msg.set_content(text)
    if html:
        msg.add_alternative(f"<html><body>{html}</body></html>", subtype="html")
    for aname, data in attachments:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=aname)
    (HERE / f"{name}.eml").write_bytes(msg.as_bytes(policy=SMTP))
    rows.append((f"{name}.eml", label))


def a(href, text):
    return f'<a href="{href}">{text}</a>'


# ---------------------------------------------------------------- malicious
mail("m01_absher_fine_ip_url", "malicious",
     frm="Absher | أبشر <no-reply@absher-notify.example>", spf="fail", dmarc="fail", ip="203.0.113.44",
     subject="تنبيه: مخالفة مرورية غير مسددة",
     text="عزيزي المستفيد،\nلديك مخالفة مرورية غير مسددة بقيمة 500 ريال. يجب سداد المبلغ خلال 24 ساعة وإلا سيتم إيقاف الخدمات.\nللسداد: http://203.0.113.10/absher/login\n",
     html="<p dir=rtl>عزيزي المستفيد،<br>لديك مخالفة مرورية غير مسددة بقيمة 500 ريال. يجب سداد المبلغ خلال 24 ساعة وإلا سيتم إيقاف الخدمات.</p>"
          f"<p>{a('http://203.0.113.10/absher/login', 'absher.sa')}</p>")

mail("m02_absher_idn_homoglyph", "malicious",
     frm=f"Absher <alerts@{AR_ABSHER}>", ip="203.0.113.45",
     subject="Absher: confirm your identity to keep your account active",
     text="Your Absher account will be suspended. Confirm your identity within 24 hours.\nhttps://" + CYR_ABSHER + "/verify\n",
     html=f"<p>Your Absher account will be suspended. Confirm your identity within 24 hours.</p><p>{a('https://' + CYR_ABSHER + '/verify', 'Continue to Absher')}</p>")

mail("m03_spl_parcel_fee", "malicious",
     frm="SPL | البريد السعودي <notice@spl-delivery.example>", reply_to="support@parcel-help.example", spf="softfail", dmarc="fail", ip="198.51.100.7",
     subject="شحنتك في انتظار سداد الرسوم الجمركية",
     text="شحنتك رقم SA4471023 معلقة. رسوم جمركية مستحقة: 15 ريال. ادفع الآن لتجنب إعادة الشحنة.\nhttps://spl.com.sa.track-parcel.example/pay\n",
     html=f"<p dir=rtl>شحنتك رقم SA4471023 معلقة. رسوم جمركية مستحقة: 15 ريال. ادفع الآن لتجنب إعادة الشحنة.</p><p>{a('https://spl.com.sa.track-parcel.example/pay', 'spl.com.sa')}</p>")

mail("m04_spl_double_ext", "malicious",
     frm="Saudi Post <tracking@splonline.example>", dmarc="fail", spf="fail", ip="198.51.100.9",
     subject="Shipment on hold - delivery fee required",
     text="Your parcel could not be delivered. Open the attached invoice to pay the delivery fee and release your parcel.\n",
     attachments=[("Shipment_Invoice.pdf.exe", MZ)])

mail("m05_alrajhi_freemail_otp", "malicious",
     frm="Al Rajhi Bank <alrajhi.alerts@gmail.com>", ip="198.51.100.20", helo="mail-sor-f41.example",
     subject="تنبيه أمني: تحقق من حسابك",
     text="عميلنا العزيز، تم رصد محاولة دخول غير معتادة. تحقق من حسابك خلال 24 ساعة وإلا سيتم إيقاف البطاقة.\nأدخل رمز التحقق هنا: https://alrajhi-secure.example/otp\n",
     html=f"<p dir=rtl>عميلنا العزيز، تم رصد محاولة دخول غير معتادة. تحقق من حسابك خلال 24 ساعة وإلا سيتم إيقاف البطاقة.</p><p>{a('https://alrajhi-secure.example/otp', 'alrajhibank.com.sa')}</p>")

mail("m06_alrajhi_typo_domain", "malicious",
     frm="AlRajhi Bank Security <security@alrajhlbank.example>", ip="203.0.113.61",
     subject="Action required: verify your account",
     text="We noticed unusual activity. Please verify your account within 24 hours or your online banking will be blocked.\nhttps://alrajhlbank.example/verify\n",
     html=f"<p>We noticed unusual activity. Please verify your account within 24 hours or your online banking will be blocked.</p><p>{a('https://alrajhlbank.example/verify', 'Verify now')}</p>")

mail("m07_aramco_hr_macro", "malicious",
     frm="Saudi Aramco HR <hr-aramco@outlook.com>", ip="198.51.100.33", helo="mail-eopbgr.example",
     subject="2026 performance bonus - eligibility list",
     text="Dear colleague,\nThe attached sheet lists employees eligible for the 2026 bonus. Open it and click Enable Content to view your figure. Respond within 48 hours.\nHR\n",
     attachments=[("Bonus_Eligibility_2026.xlsm", PK)])

mail("m08_aramco_ole_doc", "malicious",
     frm="Aramco Payroll <payroll@aramco-portal.example>", dmarc="fail", ip="203.0.113.77",
     subject="قسيمة الراتب - أكتوبر 2026",
     text="مرفق قسيمة راتبك لشهر أكتوبر. يرجى فتح الملف وتفعيل المحتوى لعرض التفاصيل.\n",
     attachments=[("Payslip_Oct2026.doc", OLE)])

mail("m09_aramco_html_smuggling", "malicious",
     frm="Aramco IT <it@aramco-it.example>", ip="203.0.113.78",
     subject="Mailbox storage full - open attached form",
     text="Your mailbox has reached its limit. Open the attached form and sign in to verify your account and release storage.\n",
     attachments=[("Payslip.html", HTML_ATT)])

mail("m10_sadad_bill_mismatch", "malicious",
     frm="SADAD | سداد <billing@sadad-pay.example>", spf="fail", dmarc="fail", ip="198.51.100.41",
     subject="فاتورة مستحقة - سيتم إيقاف الخدمة",
     text="لديك فاتورة مستحقة بقيمة 312.50 ريال. سداد المبلغ مطلوب خلال 24 ساعة.\nhttps://pay-sadad-now.example/bill\n",
     html=f"<p dir=rtl>لديك فاتورة مستحقة بقيمة 312.50 ريال. سداد المبلغ مطلوب خلال 24 ساعة.</p><p>{a('https://pay-sadad-now.example/bill', 'sadad.com')}</p>")

mail("m11_stc_userinfo_url", "malicious",
     frm="stc <noreply@stc-billing.example>", ip="203.0.113.90",
     subject="Your stc bill is overdue / فاتورتك متأخرة",
     text="Your outstanding bill of SAR 189 is overdue. Pay now to avoid suspension of your line.\nhttps://stc.com.sa@203.0.113.5/pay\n",
     html=f"<p>Your outstanding bill of SAR 189 is overdue. Pay now to avoid suspension of your line.</p><p>{a('https://stc.com.sa@203.0.113.5/pay', 'Pay bill')}</p>")

mail("m12_mygov_data_uri", "malicious",
     frm="National Unified Portal my.gov.sa <no-reply@my-gov-sa.example>", ip="203.0.113.91",
     subject="تحديث بياناتك في المنصة الوطنية الموحدة",
     text="يرجى تحديث بياناتك خلال 48 ساعة للاستمرار في استخدام الخدمات الحكومية.\n",
     html="<p dir=rtl>يرجى تحديث بياناتك خلال 48 ساعة للاستمرار في استخدام الخدمات الحكومية.</p>"
          f"<p>{a('data:text/html;base64,PGh0bWw+PGJvZHk+ZHVtbXk8L2JvZHk+PC9odG1sPg==', 'تحديث البيانات')}</p>")

mail("m13_aramex_fee_html_att", "malicious",
     frm="Aramex <delivery@aramex-ksa.example>", dmarc="none", ip="198.51.100.55",
     subject="Aramex: customs fee required to release your parcel",
     text="A customs fee of SAR 27 is pending. Open the attached invoice to pay and release your parcel.\n",
     attachments=[("Customs_Invoice.htm", HTML_ATT)])

mail("m14_smsa_qr", "malicious",
     frm="SMSA Express <notify@smsa-express.example>", spf="softfail", dmarc="fail", ip="198.51.100.56",
     subject="شحنة SMSA: رسوم جمركية مستحقة",
     text="امسح رمز QR المرفق لدفع الرسوم الجمركية (22 ريال) خلال 24 ساعة، وإلا ستعاد الشحنة.\nhttps://smsa-express.example/qr\n",
     html=f"<p dir=rtl>امسح رمز QR المرفق لدفع الرسوم الجمركية (22 ريال) خلال 24 ساعة، وإلا ستعاد الشحنة.</p><p>{a('https://smsa-express.example/qr', 'عرض الرمز')}</p>")

mail("m15_corp_it_typo_sso", "malicious",
     frm="Corp IT Helpdesk <helpdesk@c0rp.example>", ip="203.0.113.120",
     subject="Your password expires in 24 hours",
     text="Your Corp password expires in 24 hours. Update your password now to avoid losing access.\nhttps://sso.c0rp.example/reset\n",
     html=f"<p>Your Corp password expires in 24 hours. Update your password now to avoid losing access.</p><p>{a('https://sso.c0rp.example/reset', 'sso.corp.example')}</p>")

mail("m16_compromised_partner", "malicious",
     frm="Accounts - Gulf Office Supplies <accounts@gulf-office-supplies.example>", ip="203.0.113.130",
     subject="Shared invoice INV-2291 for your review",
     text="Hello,\nPlease sign in to verify your identity and view the shared invoice.\nhttps://login.corp.example.docs-share.example/\nRegards, Accounts\n",
     html=f"<p>Hello,<br>Please sign in to verify your identity and view the shared invoice.</p><p>{a('https://login.corp.example.docs-share.example/', 'View shared invoice')}</p>")

mail("m17_onenote_att", "malicious",
     frm="Fatimah Al-Otaibi <f.alotaibi.docs@hotmail.com>", reply_to="fatimah.docs.reply@gmail.com", ip="198.51.100.70", helo="mail-oln.example",
     subject="Contract for review before Thursday",
     text="Hi,\nAttached is the contract we discussed. Please review before the meeting.\nFatimah\n",
     attachments=[("Contract_Review.one", ZERO)])

mail("m18_iso_purchase_order", "malicious",
     frm="Procurement <po@corp-procurement.example>", spf="fail", dmarc="none", ip="203.0.113.140",
     subject="URGENT: Purchase order PO-88213 approval",
     text="Urgent: open the attached purchase order image and approve immediately.\n",
     attachments=[("PO_88213.iso", ZERO)])

mail("m19_lnk_scan", "malicious",
     frm="Xerox Scanner <scanner@corp.example>", spf="fail", dkim="fail", dmarc="fail", ip="198.51.100.80", helo="unknown",
     subject="Scanned document from MFP-3F",
     text="Scanned from Xerox MFP-3F. Pages: 2.\n",
     attachments=[("Scan_0021.pdf.lnk", b"L\x00\x00\x00" + ZERO)])

mail("m20_alrajhi_arabic_alef_homoglyph", "malicious",
     frm=f"Al Rajhi Bank <alerts@{AR_ALRAJHI}>", ip="203.0.113.150",
     subject="تم إيقاف بطاقتك مؤقتاً",
     text="تم إيقاف بطاقتك مؤقتاً. تحقق من حسابك لإعادة التفعيل.\nhttps://" + AR_ALRAJHI + "/login\n",
     html=f"<p dir=rtl>تم إيقاف بطاقتك مؤقتاً. تحقق من حسابك لإعادة التفعيل.</p><p>{a('https://' + AR_ALRAJHI + '/login', 'إعادة التفعيل')}</p>")

mail("m21_absher_exact_spoof_auth_fail", "malicious",
     frm="Absher <noreply@absher.sa>", return_path="bounce@mailer-x.example", spf="fail", dkim="none", dmarc="fail", ip="198.51.100.90", helo="srv-9.mailer-x.example",
     subject="إشعار مخالفة مرورية",
     text="لديك مخالفة مرورية. سداد المبلغ خلال 24 ساعة.\nhttp://198.51.100.23/absher\n",
     html=f"<p dir=rtl>لديك مخالفة مرورية. سداد المبلغ خلال 24 ساعة.</p><p>{a('http://198.51.100.23/absher', 'absher.sa')}</p>")

mail("m22_ceo_gift_cards_bec", "malicious",
     frm="Khalid Al-Dossary (CEO) <khalid.dossary.ceo@gmail.com>", reply_to="k.dossary.office@outlook.com", ip="198.51.100.100", helo="mail-sor-f41.example",
     subject="Quick favour",
     text="Are you at your desk? I need you to buy 5 gift card vouchers for a client urgently and send me the codes. Reply immediately, I am in a meeting.\nKhalid\n")

mail("m23_tax_refund_lure", "malicious",
     frm="Tax Refund Office <refund@gov-refunds.example>", spf="softfail", dmarc="none", ip="203.0.113.160",
     subject="You are eligible for a tax refund of SAR 1,240",
     text="Claim your refund within 48 hours. Confirm your identity at https://gov-refunds.example/claim\n",
     html=f"<p>Claim your refund within 48 hours.</p><p>{a('https://gov-refunds.example/claim', 'Confirm your identity')}</p>")

# ---------------------------------------------------------------- suspicious
mail("s01_forwarded_newsletter_spf_fail", "suspicious",
     frm="Riyadh Tech Meetup <hello@riyadhtech.example>", spf="fail", dkim="pass", dmarc="fail", ip="203.0.113.200", helo="lists.forwarder.example",
     subject="November meetup: agenda",
     text="Agenda for the November meetup is online: https://riyadhtech.example/nov\nSee you there.\n")

mail("s02_job_offer_docx", "suspicious",
     frm="Talent Team <recruit.gulf.talent@gmail.com>", reply_to="gulf.talent.hr@outlook.com", ip="198.51.100.110", helo="mail-sor-f41.example",
     subject="Offer letter - respond within 48 hours",
     text="Congratulations, please find your offer letter attached. Respond within 48 hours.\n",
     attachments=[("Offer_Letter.docx", PK)])

mail("s03_vendor_invoice_freemail", "suspicious",
     frm="Ahmed - Al Noor Trading <alnoor.trading.invoices@yahoo.com>", ip="198.51.100.111", helo="sonic.example",
     subject="Invoice 4471 - pending payment",
     text="Dear sir, please find attached invoice 4471, pending payment since last month.\nAhmed\n",
     attachments=[("Invoice_4471.pdf", PDF)])

mail("s04_password_zip", "suspicious",
     frm="DocuSend <noreply@docusend-mail.example>", dmarc="none", ip="203.0.113.210",
     subject="Payment confirmation",
     text="Your payment confirmation is attached. Archive password: 2026\n",
     attachments=[("Payment_Confirmation.zip", PK)])

mail("s05_hr_external_xlsx_noauth", "suspicious",
     frm="HR Department <hr@corp-hr.example>", auth=False, ip="203.0.113.211",
     subject="Salary review - confirm your details",
     text="Please open the attached sheet and confirm your details.\n",
     attachments=[("Salary_Review.xlsx", PK)])

mail("s06_fileshare_text_mismatch", "suspicious",
     frm="FileShare <share@fileshare-notify.example>", dmarc="none", ip="203.0.113.212",
     subject="A file was shared with you",
     text="A file was shared with you: https://fileshare-notify.example/d/abc\n",
     html=f"<p>A file was shared with you.</p><p>{a('https://fileshare-notify.example/d/abc', 'fileshare.example/d/abc')}</p>")

# ---------------------------------------------------------------- clean
mail("c01_it_password_policy", "clean",
     frm="Corp IT <it-notices@corp.example>", ip="192.0.2.25", helo="smtp-out.corp.example",
     subject="Password policy change effective 1 November",
     text="Your password will expire in 14 days under the new policy. Update your password through SSO: https://sso.corp.example/policy\nIT Service Desk, ext. 4400\n")

mail("c02_hr_eid_holiday_ar", "clean",
     frm="الموارد البشرية <hr@corp.example>", ip="192.0.2.25", helo="smtp-out.corp.example",
     subject="جدول إجازة اليوم الوطني",
     text="زملاءنا الأعزاء،\nتبدأ إجازة اليوم الوطني يوم الثلاثاء وتنتهي الخميس. العودة للعمل الأحد.\nالموارد البشرية\n")

mail("c03_alrajhi_otp_real", "clean",
     frm="Al Rajhi Bank <noreply@alrajhibank.com.sa>", ip="203.0.113.5",
     subject="رمز التحقق",
     text="رمز التحقق الخاص بك هو 482133. لا تشاركه مع أحد. البنك لا يطلب الرمز هاتفياً.\n")

mail("c04_spl_delivery_real", "clean",
     frm="SPL <notifications@spl.com.sa>", ip="203.0.113.6",
     subject="Your parcel SA2290113 is out for delivery",
     text="Your parcel SA2290113 is out for delivery today. Track it in the SPL app.\n")

mail("c05_stc_bill_real", "clean",
     frm="stc <ebill@stc.com.sa>", ip="203.0.113.7",
     subject="فاتورتك لشهر أكتوبر جاهزة",
     text="فاتورتك لشهر أكتوبر بقيمة 230 ريال جاهزة. يمكنك الاطلاع والسداد عبر تطبيق mystc.\n")

mail("c06_dev_newsletter_same_domain", "clean",
     frm="Dev Weekly <news@devweekly.example>", return_path="bounces@bounces.devweekly.example", ip="203.0.113.8",
     subject="Dev Weekly #412",
     text="This week: Python 3.14 beta notes, a new SQLite release, and a talk on observability.\nhttps://devweekly.example/412\n",
     html=f"<p>This week: Python 3.14 beta notes, a new SQLite release, and a talk on observability.</p><p>{a('https://devweekly.example/412', 'Read issue 412')}</p>")

mail("c07_newsletter_esp_returnpath", "clean",
     frm="Riyadh Startups Digest <digest@riyadhstartups.example>", return_path="b-123@bounce.mailsender.example", ip="203.0.113.9", helo="o1.mailsender.example",
     subject="Digest: 5 funding rounds this week",
     text="Five rounds announced this week. Full list: https://riyadhstartups.example/digest/44\n")

mail("c08_newsletter_tracking_redirect", "clean",
     frm="Gulf Retail Weekly <weekly@gulfretail.example>", return_path="b-77@bounce.mailsender.example", ip="203.0.113.9", helo="o1.mailsender.example",
     subject="Q3 retail report is out",
     text="Read the Q3 report: https://click.mailsender.example/c/789\n",
     html=f"<p>Read the Q3 report:</p><p>{a('https://click.mailsender.example/c/789', 'gulfretail.example/q3-report')}</p>")

mail("c09_intranet_private_ip", "clean",
     frm="Corp IT <it-notices@corp.example>", ip="192.0.2.25", helo="smtp-out.corp.example",
     subject="Reminder: reset your password on the new intranet",
     text="Urgent reminder for the migration: reset your password on the new intranet at http://10.20.4.15/portal before Sunday.\n")

mail("c10_security_awareness", "clean",
     frm="Corp Security <security@corp.example>", ip="192.0.2.25", helo="smtp-out.corp.example",
     subject="Phishing awareness: what the latest lures look like",
     text="This month's lures: 'verify your account', 'urgent' CEO requests for gift card codes, fake customs fee notices. Training module: https://security.corp.example/training\n")

mail("c11_aramex_real", "clean",
     frm="Aramex <notify@aramex.com>", ip="203.0.113.11",
     subject="Shipment 4420098 delivered",
     text="Your shipment 4420098 was delivered today. Delivery fee was prepaid by the sender.\n")

mail("c12_sadad_real", "clean",
     frm="SADAD <alerts@sadad.com>", ip="203.0.113.12",
     subject="تذكير: فاتورة مستحقة",
     text="لديك فاتورة مستحقة من شركة الكهرباء بقيمة 410 ريال. يمكنك السداد عبر تطبيق البنك الخاص بك.\n")

mail("c13_vendor_invoice_replyto_saas", "clean",
     frm="Noor Printing <billing@noorprinting.example>", reply_to="inv+4471@invoices.acctsaas.example", ip="203.0.113.13",
     subject="Invoice NP-4471 (pending payment)",
     text="Invoice NP-4471 for October printing is attached. Pending payment, due 15 November.\n",
     attachments=[("NP-4471.pdf", PDF)])

mail("c14_absher_appointment_real", "clean",
     frm="Absher <noreply@absher.sa>", ip="203.0.113.14",
     subject="تأكيد موعدك",
     text="تم تأكيد موعدك في الأحوال المدنية يوم الأربعاء الساعة 10:30 صباحاً. يرجى إحضار الهوية.\n")

mail("c15_university_notice_ar", "clean",
     frm="عمادة القبول والتسجيل <admissions@uni.example>", ip="203.0.113.15",
     subject="عاجل: تعديل موعد الاختبارات النهائية",
     text="تم تعديل موعد الاختبارات النهائية ليبدأ يوم 15 ديسمبر. الجدول المحدث على البوابة الأكاديمية.\n")

mail("c16_calendar_invite", "clean",
     frm="Sara Al-Mutairi <sara.almutairi@corp.example>", ip="192.0.2.25", helo="smtp-out.corp.example",
     subject="Invitation: SOC weekly sync",
     text="SOC weekly sync, Tuesday 11:00, room 3B.\n",
     attachments=[("invite.ics", b"BEGIN:VCALENDAR\nVERSION:2.0\nEND:VCALENDAR\n")])

mail("c17_gitforge_notification", "clean",
     frm="GitForge <notifications@gitforge.example>", return_path="noreply@gitforge.example", ip="203.0.113.17",
     subject="[corp/detections] PR #88: add DMARC fail rule",
     text="New pull request: add DMARC fail rule.\nhttps://gitforge.example/corp/detections/pull/88\n",
     html=f"<p>New pull request: add DMARC fail rule.</p><p>{a('https://gitforge.example/corp/detections/pull/88', 'View pull request')}</p>")

mail("c18_mailing_list_spf_fail_dkim_pass", "clean",
     frm="Omar Hassan <omar.hassan@partner-lab.example>", spf="fail", dkim="pass", dmarc="pass", return_path="list-bounces@lists.infosec-ksa.example", ip="203.0.113.18", helo="lists.infosec-ksa.example",
     subject="[infosec-ksa] Slides from yesterday's talk",
     text="Slides are up: https://partner-lab.example/talks/dmarc\n")

mail("c19_mfa_enrollment", "clean",
     frm="Corp Identity <identity@corp.example>", ip="192.0.2.25", helo="smtp-out.corp.example",
     subject="Enrol your second factor by 30 November",
     text="Enrol your authenticator app before 30 November: https://id.corp.example/enrol\nIdentity team\n",
     html=f"<p>Enrol your authenticator app before 30 November.</p><p>{a('https://id.corp.example/enrol', 'id.corp.example/enrol')}</p>")

mail("c20_recruiter_legit_domain", "clean",
     frm="Lama Khan <lama.khan@talentbridge.example>", dmarc="none", ip="203.0.113.20",
     subject="Interview slot - SOC analyst intern",
     text="Hi Mohsen, can you confirm a slot within 48 hours? Job description attached.\n",
     attachments=[("JD_SOC_Intern.pdf", PDF)])

mail("c21_bank_statement_real", "clean",
     frm="Al Rajhi Bank <statements@alrajhibank.com.sa>", ip="203.0.113.5",
     subject="كشف حساب أكتوبر",
     text="كشف حسابك لشهر أكتوبر متاح الآن في التطبيق. لا يحتوي هذا البريد على روابط.\n")

mail("c22_forwarded_by_user_auth_broken", "clean",
     frm="Corp Security <security@corp.example>", return_path="sara.alharbi@mail.example", spf="fail", dkim="none", dmarc="fail", ip="198.51.100.20", helo="mail-sor-f41.example",
     subject="Fwd: Phishing awareness session Tuesday",
     text="Forwarding in case you missed it.\n\n---------- Forwarded message ---------\nReminder: phishing awareness session Tuesday 10:00, room 2A.\n")

with (HERE / "labels.csv").open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["file", "label"])
    w.writerows(rows)
print(f"wrote {len(rows)} emails")
