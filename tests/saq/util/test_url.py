import pytest

from saq.util.url import sanitize_protected_url

@pytest.mark.parametrize('source_url,expected_url', [
    ('https://no.changes.com/test', 'https://no.changes.com/test'),
    # URLDefense examples
    ('https://urldefense.com/v3/__http://blog.liulianshuo.cn/miseryzw.php?utm_source=commanded&utm_medium=besmirch&utm_campaign=subtractions__;!!MwwqYLOC6b6whF7V!0-s0cwelKF9e6ILM8eHxQsPJoSKGEKwWBcpxrsmug65gs1IGv-y98xCoFqPZtGQECqDgirvyJA$', 'http://blog.liulianshuo.cn/miseryzw.php?utm_source=commanded&utm_medium=besmirch&utm_campaign=subtractions'),
    ('https://urldefense.com/v3/__http://www.chicagoent.com__;!!MwwqYLOC6b6whF7V!hlFzJJKSgy_yhExaSf_rO2F3t91Y9EI7KMYvQDBN2Pg8rge0Hx-1191NfRJ24_qo96oG0ghxKHs1kWnuNeboNZpokHY$  [https://urldefense.com/v3/__https://chicagoent.com/__;!!MwwqYLOC6b6whF7V!hlFzJJKSgy_yhExaSf_rO2F3t91Y9EI7KMYvQDBN2Pg8rge0Hx-1191NfRJ24_qo96oG0ghxKHs1kWnuNeborJICOjM$ ]', 'http://www.chicagoent.com'),
    # FireEye example
    ('https://protect2.fireeye.com/url?k=80831952-dcdfed5d-808333ca-0cc47a33347c-b424c0fc7973027a&u=https://mresearchsurveyengine.modernsurvey.com/Default.aspx?cid=201c1f2c-2bdc-11ea-a81b-000d3aaced43', 'https://mresearchsurveyengine.modernsurvey.com/Default.aspx?cid=201c1f2c-2bdc-11ea-a81b-000d3aaced43'),
    # Outlook Safelinks example
    ('https://na01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fwww.getbusinessready.com.au%2FInvoice-Number-49808%2F', 'http://www.getbusinessready.com.au/Invoice-Number-49808/'),
    # Dropbox example (dl=0 -> dl=1)
    ('https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=0', 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1'),
    # Google Drive example
    ('https://drive.google.com/file/d/1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2/view', 'https://drive.google.com/uc?authuser=0&id=1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2&export=download'),
    # Sharepoint example
    ('https://lahia-my.sharepoint.com/:b:/g/personal/secure_onedrivemsw_bid/EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ?e=naeXYD', 'https://lahia-my.sharepoint.com/personal/secure_onedrivemsw_bid/_layouts/15/download.aspx?e=naeXYD&share=EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ'),
    # URLDefense Proofpoint example
    ('https://urldefense.proofpoint.com/v2/url?u=http-3A__www.linkedin.com_company_totallyrealcompany_&d=DwMFAg&c=h4Hco3TqWGhswFY_DB9a0ROb2nz1Kbox_73PUtgNn3M&r=e535Fw3IpJvnSZEQ8eSBhv2S1aSylN4En6TbrM0pu-s&m=LtdAZpeaQEez66l8y9cdhXQ-AQyHhRF7ueGZFY4vMBY&s=2fSW-t6FWhm0XTwMy8e-MeYldedFppe3AtXxlEH8t4A&e=', 'http://www.linkedin.com/company/totallyrealcompany'),
    # ...
    ('https://secure-web.cisco.com/1tlPsGZcvzBZyF6NpjvqyfqF58WnrQLomPj19oOwYBXNSPw1XvdHVJpdn4voWDGV0z1edLQLVxlOUf97S3LkBDEqZ_nXGjLkCfKTHb2z7IcLg7ojBsEuagFQXSQnwAJry8m1DoDlCsnhL03BXxECOSt21sPk9ZoeGFpq1mG2z5yVInYa8eowpnrQ3n3fK5TreSxtmzXYe6kFJl2YYm5o7Yk8Go4K3n5_YYqTetUgQhcoTntOlED3zu5hOSORlYFVKifK9JfHm7QTQhF-3beICoQg6yjvSY80Qi9NUNefEzypuJMH37tB4HUXScxZbqtTUGocWRhfhOq-VsgB95vcixwvBpAz0MRxp20wfDT8sTXGw0YdGXQZ4BPlfASqYgYex0anNkcWuQ332F6mmGWXAxAjGsgL8gdp3Fgn7Sd2cvTs/https%3A%2F%2Fus-west-2.protection.sophos.com%2F%3Fd%3Dcudasvc.com%26u%3DaHR0cHM6Ly9saW5rcHJvdGVjdC5jdWRhc3ZjLmNvbS91cmw_YT1odHRwcyUzYSUyZiUyZnNlY3VyZS5zZXJrYXNlcmlncmFmaS5jb20lMmYmYz1FLDEsNm9DcVp1RXdOVXkwOFJ1ejNVMUY1N0FBTkJVbE5kNjlmYXE2UFAwNFB0TTZjRE0ycnc3WG1vaUJNWWV5MEZ0WldaelphaU5DQWZZYVZOd1VRZ2o3OC1UUWF4UHd3ek1hVl9qSm5lb05BQSwsJnR5cG89MQ%3D%3D%26p%3Dm%26i%3DNjI0NWJmMTk0YzU3ZDAxMDkwNjAwMzI3%26t%3DRlVkbkxaSUR4Nm9sSGlKWGVWS1FBaUlTOUZZNGxtUHVIT1B2MFUzcVhWdz0%3D%26h%3D74ce429d578c45ff895e22f7a0b40a7c%26s%3DAVNPUEhUT0NFTkNSWVBUSVanqsQVge8U6-_iPt463foLN-OF69MpSkFFwaQp-z8AVQ#bbea5a886ba5ce04f95eded721586e4f69595fda=eGlhb21AYnYuY29t', 'https://secure.serkaserigrafi.com/')
])
@pytest.mark.unit
def test_urldefense_url(source_url, expected_url):
    assert sanitize_protected_url(source_url) == expected_url