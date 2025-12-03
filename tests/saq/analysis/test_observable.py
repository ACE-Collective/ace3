# vim: sw=4:ts=4:et:cc=120
import datetime
import pytest
import time

from saq.configuration import get_config
from saq.constants import DISPOSITION_DELIVERY, F_ASSET, F_EMAIL_ADDRESS, F_EMAIL_DELIVERY, F_FILE, F_FILE_LOCATION, F_FILE_NAME, F_FILE_PATH, F_FQDN, F_HOSTNAME, F_INDICATOR, F_IPV4, F_MAC_ADDRESS, F_MD5, F_MESSAGE_ID, F_SHA256, F_SNORT_SIGNATURE, F_TEST, F_URL, F_USER, F_YARA_RULE, create_email_delivery
from saq.database import get_db
from saq.observables import create_observable
from tests.saq.helpers import create_root_analysis


@pytest.mark.unit
def test_fqdn_observable():
    o = create_observable(F_FQDN, 'not a valid fqdn')
    assert o is None

    o = create_observable(F_FQDN, 'localhost.localdomain')
    assert o.value == 'localhost.localdomain'

    o = create_observable(F_FQDN, 'domain.com')
    assert o.value == 'domain.com'

    # test punycode domain
    o = create_observable(F_FQDN, 'xn--mnich-kva.com')
    assert o.value == 'xn--mnich-kva.com'


@pytest.mark.unit
def test_snort_signature_observable():
    o = create_observable(F_SNORT_SIGNATURE, '1:2802042:3')
    assert o.signature_id == '2802042'
    assert o.rev == '3'

    o = create_observable(F_SNORT_SIGNATURE, '1:2802042')
    assert o.signature_id is None
    assert o.rev is None


@pytest.mark.integration
def test_observable_expires_on(db_event):
    from saq.database import Alert, ALERT, Campaign, EventMapping, Observable, ObservableMapping, User, set_dispositions

    get_config()['observable_expiration_mappings'][F_TEST] = '01:00:00:00'

    # Create an analysis that turns into an alert
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, 'test_detection')
    root.save()

    ALERT(root)

    # Get the expires_on time of the observable in the alert
    expires_on_original = get_db().query(Observable.expires_on) \
        .join(ObservableMapping, Observable.id == ObservableMapping.observable_id) \
        .join(Alert, ObservableMapping.alert_id == Alert.id) \
        .filter(Alert.uuid == root.uuid).one().expires_on

    # The expires_on value should be greater than now() based on the 01:00:00:00 configured delta
    assert expires_on_original > datetime.datetime.now()

    # Set the disposition of this alert to something malicious after sleeping for a second
    time.sleep(1)
    set_dispositions([root.uuid], DISPOSITION_DELIVERY, get_db().query(User).first().id)

    # Get the updated expires_on time of the observable in the alert
    expires_on_updated = get_db().query(Observable.expires_on) \
        .join(ObservableMapping, Observable.id == ObservableMapping.observable_id) \
        .join(Alert, ObservableMapping.alert_id == Alert.id) \
        .filter(Alert.uuid == root.uuid).one().expires_on

    # The expires_on time should have been updated by virtue of setting the alert disposition
    assert expires_on_updated > expires_on_original

    # Add the alert to the event
    alert_id = get_db().query(Alert.id).filter(Alert.uuid == root.uuid).one().id
    event_mapping = EventMapping(event_id=db_event.id, alert_id=alert_id)
    get_db().add(event_mapping)
    get_db().commit()

    # Add a threat actor to the event
    threat_actor = Campaign(name='Test Actor')
    get_db().add(threat_actor)
    db_event.campaign = threat_actor
    get_db().commit()

    # Pretend to close the event and call the _nullify_expires_on_if_threat_actor function, which normally gets called
    # as part of event_closing_tasks() when the event is actually closed.
    #_nullify_expires_on_if_threat_actor(db_event)

    # Get the final expires_on time of the observable in the alert
    expires_on_closed = get_db().query(Observable.expires_on) \
        .join(ObservableMapping, Observable.id == ObservableMapping.observable_id) \
        .join(Alert, ObservableMapping.alert_id == Alert.id) \
        .filter(Alert.uuid == root.uuid).one().expires_on

    # The expires_on time should now be null since the event was closed with a threat actor assigned
    #assert expires_on_closed is None

@pytest.mark.unit
def test_observable_sha256():
    
    root = create_root_analysis()
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    assert observable
    assert observable.sha256_hash == '38a810ebdd0b91253efbaf708316ec74cb659ccc6bfdd915df06a4ab2b31f877'

# expected values
EV_OBSERVABLE_ASSET = 'localhost'
EV_OBSERVABLE_SNORT_SIGNATURE = '2809768'
EV_OBSERVABLE_EMAIL_ADDRESS = 'jwdavison@valvoline.com'
EV_OBSERVABLE_FILE = 'var/test.txt'
EV_OBSERVABLE_FILE_LOCATION = r'PCN31337@C:\users\lol.txt'
EV_OBSERVABLE_FILE_NAME = 'evil.exe'
EV_OBSERVABLE_FILE_PATH = r'C:\windows\system32\notepod.exe'
EV_OBSERVABLE_FQDN = 'evil.com'
EV_OBSERVABLE_HOSTNAME = 'adserver'
EV_OBSERVABLE_INDICATOR = '5a1463a6ad951d7088c90de4'
EV_OBSERVABLE_IPV4 = '1.2.3.4'
EV_OBSERVABLE_MD5 = 'f233d34c98f6bb32bb3b3ce7e740eb84'
EV_OBSERVABLE_SHA256 = '2206014de326cf3151bcebcfa89bd380c06339680989cd85f3791e81424b27ec'
EV_OBSERVABLE_URL = 'http://www.evil.com/blah.exe'
EV_OBSERVABLE_USER = 'a420539'
EV_OBSERVABLE_YARA_RULE = 'CRITS_URIURL'
EV_OBSERVABLE_MESSAGE_ID = '<E07DC80D-9F7E-4B7D-8338-82D37ACBC80A@burtbrothers.com>'
EV_OBSERVABLE_PROCESS_GUID = '00000043-0000-2c8c-01d3-63e9f520f17c'

EV_OBSERVABLE_VALUE_MAP = {
    F_ASSET: EV_OBSERVABLE_ASSET,
    F_SNORT_SIGNATURE: EV_OBSERVABLE_SNORT_SIGNATURE,
    F_EMAIL_ADDRESS: EV_OBSERVABLE_EMAIL_ADDRESS,
    #F_FILE: EV_OBSERVABLE_FILE,
    F_FILE_LOCATION: EV_OBSERVABLE_FILE_LOCATION,
    F_FILE_NAME: EV_OBSERVABLE_FILE_NAME,
    F_FILE_PATH: EV_OBSERVABLE_FILE_PATH,
    F_FQDN: EV_OBSERVABLE_FQDN,
    F_HOSTNAME: EV_OBSERVABLE_HOSTNAME,
    F_INDICATOR: EV_OBSERVABLE_INDICATOR,
    F_IPV4: EV_OBSERVABLE_IPV4,
    F_MD5: EV_OBSERVABLE_MD5,
    F_SHA256: EV_OBSERVABLE_SHA256,
    F_URL: EV_OBSERVABLE_URL,
    F_USER: EV_OBSERVABLE_USER,
    F_YARA_RULE: EV_OBSERVABLE_YARA_RULE,
    F_MESSAGE_ID: EV_OBSERVABLE_MESSAGE_ID,
}

def add_observables(root):
    for o_type in EV_OBSERVABLE_VALUE_MAP.keys():
        root.add_observable_by_spec(o_type, EV_OBSERVABLE_VALUE_MAP[o_type])

@pytest.mark.unit
def test_add_observable():
    root = create_root_analysis()
    add_observables(root)

@pytest.mark.unit
def test_add_invalid_observables():
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_IPV4, '1.2.3.4.5')
    assert observable is None
    # XXX broken after upgrade
    #o = root.add_observable_by_spec(F_URL, '\xFF')
    #self.assertIsNone(o)
    assert root.add_file_observable("") is None

@pytest.mark.unit
def test_observable_storage():
    root = create_root_analysis()
    add_observables(root)
    root.save()

    root = create_root_analysis()
    root.load()

    for o_type in EV_OBSERVABLE_VALUE_MAP.keys():
        observable = root.get_observable_by_type(o_type)
        assert observable
        assert observable.type == o_type
        assert observable.value == EV_OBSERVABLE_VALUE_MAP[o_type]

@pytest.mark.unit
def test_caseless_observables():
    root = create_root_analysis()
    observable_1 = root.add_observable_by_spec(F_HOSTNAME, 'abc')
    observable_2 = root.add_observable_by_spec(F_HOSTNAME, 'ABC')
    # the second should return the same object
    assert observable_1 is observable_2
    assert observable_2.value == 'abc'

@pytest.mark.unit
def test_file_type_observables():
    root = create_root_analysis()
    file_path = root.create_file_path("sample.txt")
    with open(file_path, "wb") as fp:
        fp.write(b"")

    observable_1 = root.add_file_observable(file_path)
    observable_2 = root.add_observable_by_spec(F_FILE_NAME, observable_1.file_name)

    # the second should NOT return the same object
    assert not ( observable_1 is observable_2 )

@pytest.mark.unit
def test_ipv6_observable():
    root = create_root_analysis()
    # this should not add an observable since this is an ipv6 address
    observable = root.add_observable_by_spec(F_IPV4, '::1')
    assert observable is None

@pytest.mark.unit
def test_add_invalid_message_id():
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_MESSAGE_ID, 'CANTOGZtOdse1SqNtFRs2o22ohrWpbddWfCzkzn+iy1SEHxt2pg@mail.gmail.com')
    assert observable.value == '<CANTOGZtOdse1SqNtFRs2o22ohrWpbddWfCzkzn+iy1SEHxt2pg@mail.gmail.com>'

@pytest.mark.unit
def test_add_invalid_email_delivery_message_id():
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_EMAIL_DELIVERY, create_email_delivery('CANTOGZtOdse1SqNtFRs2o22ohrWpbddWfCzkzn+iy1SEHxt2pg@mail.gmail.com', 'test@localhost.com'))
    assert observable.value == '<CANTOGZtOdse1SqNtFRs2o22ohrWpbddWfCzkzn+iy1SEHxt2pg@mail.gmail.com>|test@localhost.com'

@pytest.mark.unit
def test_valid_mac_observable():
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_MAC_ADDRESS, '001122334455')
    assert observable
    assert observable.value == '001122334455'
    assert observable.mac_address() == '00:11:22:33:44:55'
    assert observable.mac_address(sep='-') == '00-11-22-33-44-55'

    observable = root.add_observable_by_spec(F_MAC_ADDRESS, '00:11:22:33:44:55')
    assert observable
    assert observable.value == '00:11:22:33:44:55'
    assert observable.mac_address(sep='') == '001122334455'

@pytest.mark.unit
def test_invalid_mac_observable():
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_MAC_ADDRESS, '00112233445Z')
    assert observable is None

@pytest.mark.unit
def test_display_type_with_no_custom_display():
    """test that display_type returns the type when no custom display_type is set"""
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_IPV4, '1.2.3.4')
    assert observable.display_type == F_IPV4
    assert observable.display_type == observable.type

@pytest.mark.unit
def test_display_type_with_custom_display():
    """test that display_type returns custom display with type in parentheses when display_type is set"""
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_IPV4, '1.2.3.4')
    observable.display_type = "Internal IP"
    assert observable.display_type == f"Internal IP ({F_IPV4})"
    assert observable.type == F_IPV4

@pytest.mark.unit
def test_display_value_with_no_custom_display():
    """test that display_value returns the value when no custom display_value is set"""
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_FQDN, 'example.com')
    assert observable.display_value == 'example.com'
    assert observable.display_value == observable.value

@pytest.mark.unit
def test_display_value_with_custom_display():
    """test that display_value returns custom display with value in parentheses when display_value is set"""
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_FQDN, 'example.com')
    observable.display_value = "Example Domain"
    assert observable.display_value == "Example Domain (example.com)"
    assert observable.value == 'example.com'

@pytest.mark.unit
def test_display_properties_combined():
    """test that both display_type and display_value work together correctly"""
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_USER, 'john.doe')

    # initially no custom display set
    assert observable.display_type == F_USER
    assert observable.display_value == 'john.doe'

    # set custom display values
    observable.display_type = "Domain User"
    observable.display_value = "John Doe"

    # verify custom display is applied
    assert observable.display_type == f"Domain User ({F_USER})"
    assert observable.display_value == "John Doe (john.doe)"

    # verify underlying properties remain unchanged
    assert observable.type == F_USER
    assert observable.value == 'john.doe'

@pytest.mark.unit
def test_display_properties_with_empty_string():
    """test that empty string is treated as None for display properties"""
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_HOSTNAME, 'webserver01')

    # set to empty string
    observable.display_type = ""
    observable.display_value = ""

    # empty strings are falsy, so should show with parentheses
    assert observable.display_type == f" ({F_HOSTNAME})"
    assert observable.display_value == " (webserver01)"

@pytest.mark.unit
def test_display_properties_persist_through_serialization():
    """test that custom display properties persist through JSON serialization"""
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, 'http://evil.com/malware.exe')

    # set custom display
    observable.display_type = "Malicious URL"
    observable.display_value = "Known Phishing Site"

    # save and reload
    root.save()
    root = create_root_analysis()
    root.load()

    # retrieve the observable
    observable = root.get_observable_by_type(F_URL)
    assert observable

    # verify custom display persisted
    assert observable.display_type == f"Malicious URL ({F_URL})"
    assert observable.display_value == "Known Phishing Site (http://evil.com/malware.exe)"

@pytest.mark.unit
def test_display_properties_reset_to_none():
    """test that display properties can be reset to None"""
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_EMAIL_ADDRESS, 'test@example.com')

    # set custom display
    observable.display_type = "Corporate Email"
    observable.display_value = "Test User"
    assert observable.display_type == f"Corporate Email ({F_EMAIL_ADDRESS})"
    assert observable.display_value == "Test User (test@example.com)"

    # reset to None
    observable.display_type = None
    observable.display_value = None

    # verify back to default behavior
    assert observable.display_type == F_EMAIL_ADDRESS
    assert observable.display_value == 'test@example.com'

@pytest.mark.unit
def test_display_properties_with_special_characters():
    """test that display properties handle special characters correctly"""
    root = create_root_analysis()
    observable = root.add_observable_by_spec(F_FILE_PATH, r'C:\Windows\System32\cmd.exe')

    # set display with special characters
    observable.display_type = "System Binary"
    observable.display_value = "Command Prompt (Admin)"

    assert observable.display_type == f"System Binary ({F_FILE_PATH})"
    assert observable.display_value == r"Command Prompt (Admin) (C:\Windows\System32\cmd.exe)"
    assert observable.value == r'C:\Windows\System32\cmd.exe'

@pytest.mark.unit
def test_protected_url_sanitization():
    root = create_root_analysis()

    # FireEye
    # taken from an actual sample
    observable = root.add_observable_by_spec(F_URL, 'https://protect2.fireeye.com/url?k=80831952-dcdfed5d-808333ca-0cc47a33347c-b424c0fc7973027a&u=https://mresearchsurveyengine.modernsurvey.com/Default.aspx?cid=201c1f2c-2bdc-11ea-a81b-000d3aaced43')
    assert observable
    assert observable.value == 'https://mresearchsurveyengine.modernsurvey.com/Default.aspx?cid=201c1f2c-2bdc-11ea-a81b-000d3aaced43'

    # Outlook Safelinks
    # taken from an actual sample
    observable = root.add_observable_by_spec(F_URL, 'https://na01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fwww.getbusinessready.com.au%2FInvoice-Number-49808%2F')
    assert observable
    assert observable.value == 'http://www.getbusinessready.com.au/Invoice-Number-49808/'

    # Dropbox w/ dl0
    # taken from an actual sample
    observable = root.add_observable_by_spec(F_URL, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=0')
    assert observable
    assert observable.value == 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1'

    # Dropbox w/ dl1
    # taken from an actual sample
    observable = root.add_observable_by_spec(F_URL, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1')
    assert observable
    assert observable.value == 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1'

    # Dropbox w/0 dl
    # taken from an actual sample
    observable = root.add_observable_by_spec(F_URL, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1')
    assert observable
    assert observable.value == 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1'

    # Google Drive
    # taken from an actual sample
    observable = root.add_observable_by_spec(F_URL, 'https://drive.google.com/file/d/1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2/view')
    assert observable
    assert observable.value == 'https://drive.google.com/uc?authuser=0&id=1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2&export=download'

    # Sharepoint
    # taken from an actual sample
    observable = root.add_observable_by_spec(F_URL, 'https://lahia-my.sharepoint.com/:b:/g/personal/secure_onedrivemsw_bid/EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ?e=naeXYD')
    assert observable
    assert observable.value == 'https://lahia-my.sharepoint.com/personal/secure_onedrivemsw_bid/_layouts/15/download.aspx?e=naeXYD&share=EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ'

    # URLDefense Proofpoint
    # taken from an actual sample
    observable = root.add_observable_by_spec(F_URL, 'https://urldefense.proofpoint.com/v2/url?u=http-3A__www.linkedin.com_company_totallyrealcompany_&d=DwMFAg&c=h4Hco3TqWGhswFY_DB9a0ROb2nz1Kbox_73PUtgNn3M&r=e535Fw3IpJvnSZEQ8eSBhv2S1aSylN4En6TbrM0pu-s&m=LtdAZpeaQEez66l8y9cdhXQ-AQyHhRF7ueGZFY4vMBY&s=2fSW-t6FWhm0XTwMy8e-MeYldedFppe3AtXxlEH8t4A&e=')
    assert observable
    assert observable.value == 'http://www.linkedin.com/company/totallyrealcompany'

    # URLDefense Proofpoint/Fireeye Combo Madness
    # taken from an actual sample
    observable = root.add_observable_by_spec(F_URL, 'https://urldefense.proofpoint.com/v2/url?u=https-3A__protect2.fireeye.com_url-3Fk-3Df3596ad8-2Daf059ed7-2Df3594040-2D0cc47a33347c-2Db1379a967f6ec2a8-26u-3Dhttps-3A__urldefense.proofpoint.com_v2_url-3Fu-3Dhttps-2D3A-5F-5Fprotect2.fireeye.com-5Furl-2D3Fk-2D3D5983ce8e-2D2D05df3a81-2D2D5983e416-2D2D0cc47a33347c-2D2Db736011c9591da20-2D26u-2D3Dhttps-2D3A-5F-5Furldefense.proofpoint.com-5Fv2-5Furl-2D3Fu-2D3Dhttps-2D2D3A-2D5F-2D5Fprotect2.fireeye.com-2D5Furl-2D2D3Fk-2D2D3D630394ed-2D2D2D3f5f60e2-2D2D2D6303be75-2D2D2D0cc47a33347c-2D2D2Df26cc16f40c18200-2D2D26u-2D2D3Dhttps-2D2D3A-2D5F-2D5Furldefense.proofpoint.com-2D5Fv2-2D5Furl-2D2D3Fu-2D2D3Dhttp-2D2D2D3A-2D2D5F-2D2D5Fwww.linkedin.com-2D2D5Fcompany-2D2D5Ftotallyrealcompany-2D2D5F-2D2D26d-2D2D3DDwMFAg-2D2D26c-2D2D3Dh4Hco3TqWGhswFY-2D2D5FDB9a0ROb2nz1Kbox-2D2D5F73PUtgNn3M-2D2D26r-2D2D3De535Fw3IpJvnSZEQ8eSBhv2S1aSylN4En6TbrM0pu-2D2D2Ds-2D2D26m-2D2D3DGtSaIiLArRMXvbOBKlOs-2D2D5F4yxwE6P49wsvutw-2D2D2DijYQh0-2D2D26s-2D2D3D7bZ99KQTH9nS5imIpd-2D2D2DJzvnZFw9ERrsjIdg2z1I4J6I-2D2D26e-2D2D3D-2D26d-2D3DDwMFAg-2D26c-2D3Dh4Hco3TqWGhswFY-2D5FDB9a0ROb2nz1Kbox-2D5F73PUtgNn3M-2D26r-2D3De535Fw3IpJvnSZEQ8eSBhv2S1aSylN4En6TbrM0pu-2D2Ds-2D26m-2D3Dxyq6Yo3B1xVbbTSXGlQGdU8k36EEV7CHygmOHWj7Nzs-2D26s-2D3Dnj2rkZV-2D5Fcbd-2D2Dxh8ZUbogYdPvh7g1USiN6Z-2D2DTDsbnSX4-2D26e-2D3D-26d-3DDwMFAg-26c-3Dh4Hco3TqWGhswFY-5FDB9a0ROb2nz1Kbox-5F73PUtgNn3M-26r-3D3YDOoqTbITmofAQVMp7EhActrtmHr3LoAgDhmn8UZiM-26m-3DO3gQS5WDwuWVhbqTn-2Dfy6D-5FMXhKla9QN2BvH2H4Ay3E-26s-3D06VTIoNrqWBoKjTqw2NbowdtYkJ6rXoE09t2MYP2y1A-26e-3D&d=DwMFAg&c=h4Hco3TqWGhswFY_DB9a0ROb2nz1Kbox_73PUtgNn3M&r=3YDOoqTbITmofAQVMp7EhActrtmHr3LoAgDhmn8UZiM&m=FpHC5Oc7qNeFXDlQwA4aK8As-NZs6w5zqMuioHJ6SEA&s=z1xJfjrUUuF4YZhi3kS3P0eZhAIpK29vKMeXEN0CcPU&e=')
    assert observable
    assert observable.value == 'http://www.linkedin.com/company/totallyrealcompany'

    # ProofPoint quintuple nested malformed madness
    # taken from an actual sample
    # XXX broken after upgrade
    #observable = root.add_observable_by_spec(F_URL, 'https://protect2.fireeye.com/url-3Fk-3Df3596ad8-af059ed7-f3594040-0cc47a33347c-b1379a967f6ec2a8-26u-3Dhttps://urldefense.proofpoint.com/v2/url-3Fu-3Dhttps-3A-5F-5Fprotect2.fireeye.com-5Furl-3Fk-3D5983ce8e-2D05df3a81-2D5983e416-2D0cc47a33347c-2Db736011c9591da20-26u-3Dhttps-3A-5F-5Furldefense.proofpoint.com-5Fv2-5Furl-3Fu-3Dhttps-2D3A-5F-5Fprotect2.fireeye.com-5Furl-2D3Fk-2D3D630394ed-2D2D3f5f60e2-2D2D6303be75-2D2D0cc47a33347c-2D2Df26cc16f40c18200-2D26u-2D3Dhttps-2D3A-5F-5Furldefense.proofpoint.com-5Fv2-5Furl-2D3Fu-2D3Dhttp-2D2D3A-2D5F-2D5Fwww.linkedin.com-2D5Fcompany-2D5Ftotallyrealcompany-2D5F-2D26d-2D3DDwMFAg-2D26c-2D3Dh4Hco3TqWGhswFY-2D5FDB9a0ROb2nz1Kbox-2D5F73PUtgNn3M-2D26r-2D3De535Fw3IpJvnSZEQ8eSBhv2S1aSylN4En6TbrM0pu-2D2Ds-2D26m-2D3DGtSaIiLArRMXvbOBKlOs-2D5F4yxwE6P49wsvutw-2D2DijYQh0-2D26s-2D3D7bZ99KQTH9nS5imIpd-2D2DJzvnZFw9ERrsjIdg2z1I4J6I-2D26e-2D3D-26d-3DDwMFAg-26c-3Dh4Hco3TqWGhswFY-5FDB9a0ROb2nz1Kbox-5F73PUtgNn3M-26r-3De535Fw3IpJvnSZEQ8eSBhv2S1aSylN4En6TbrM0pu-2Ds-26m-3Dxyq6Yo3B1xVbbTSXGlQGdU8k36EEV7CHygmOHWj7Nzs-26s-3Dnj2rkZV-5Fcbd-2Dxh8ZUbogYdPvh7g1USiN6Z-2DTDsbnSX4-26e-3D-26d-3DDwMFAg-26c-3Dh4Hco3TqWGhswFY-5FDB9a0ROb2nz1Kbox-5F73PUtgNn3M-26r-3D3YDOoqTbITmofAQVMp7EhActrtmHr3LoAgDhmn8UZiM-26m-3DO3gQS5WDwuWVhbqTn-fy6D-5FMXhKla9QN2BvH2H4Ay3E-26s-3D06VTIoNrqWBoKjTqw2NbowdtYkJ6rXoE09t2MYP2y1A-26e-3D')
    #self.assertIsNone(observable)