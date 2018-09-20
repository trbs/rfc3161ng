import os.path
import datetime
import dateutil.tz
import subprocess

from tempfile import NamedTemporaryFile
# from pyasn1.type import univ
from pyasn1.codec.der import encoder

import rfc3161ng


def _default_test(tsa_server, certificate, username=None, password=None, data='xx', nonce=None, **kwargs):
    with open(certificate, 'rb') as f:
        certificate_data = f.read()

    kwargs.update({
        'certificate': certificate_data,
    })
    if username and password:
        kwargs.update({
            'username': username,
            'password': password,
        })

    timestamper = rfc3161ng.RemoteTimestamper(tsa_server, **kwargs)
    kwargs = {}
    if nonce:
        kwargs['nonce'] = nonce
    value = timestamper(data=data, **kwargs)
    assert value is not False
    assert isinstance(rfc3161ng.get_timestamp(value), datetime.datetime)
    assert value is not None


def test_verify_timestamp_response_with_openssl():
    with open(os.path.join(os.path.dirname(__file__), '../data/freetsa.crt'), 'rb') as f:
        certificate_data = f.read()

    timestamper = rfc3161ng.RemoteTimestamper('http://freetsa.org/tsr', certificate=certificate_data)

    with NamedTemporaryFile() as data_f, NamedTemporaryFile() as tsr_f:
        data_f.write(b"Hello World from rfc3161ng\n")
        data_f.flush()
        data_f.seek(0)

        tsr = timestamper(data=data_f.read(), return_tsr=True)
        tsr_f.write(encoder.encode(tsr))
        tsr_f.flush()

        args = ["openssl", "ts", "-verify", "-data", data_f.name, "-in", tsr_f.name, "-CAfile", "data/freetsa_cacert.pem", "-untrusted", "data/freetsa.crt"]
        subprocess.check_call(args)


def test_time_certum_pl():
    _default_test(
        'http://time.certum.pl',
        os.path.join(os.path.dirname(__file__), '../data/certum_certificate.crt'),
    )


def test_freetsa_org():
    _default_test(
        'http://freetsa.org/tsr',
        os.path.join('data/freetsa.crt'),
    )


def test_teszt_e_szigno_hu():
    data = '{"comment": "Envoi en Commission", "to": "Benjamin Dauvergne", "filetype": "Arr\u00eat CC", "from": "Benjamin Dauvergne", "files": [{"name": "affectations_ange1d.xlsx", "digest": "ce57e4ba353107dddaab91b9ad26c0569ffe0f94", "size": 16279}]}'
    _default_test(
        'https://teszt.e-szigno.hu:440/tsa',
        username='teszt',
        password='teszt',
        certificate=os.path.join(os.path.dirname(__file__), '../data/e_szigno_test_tsa2.crt'),
        data=data,
        hashname='sha256',
    )


def test_teszt_e_szigno_hu_with_nonce():
    data = '{"comment": "Envoi en Commission", "to": "Benjamin Dauvergne", "filetype": "Arr\u00eat CC", "from": "Benjamin Dauvergne", "files": [{"name": "affectations_ange1d.xlsx", "digest": "ce57e4ba353107dddaab91b9ad26c0569ffe0f94", "size": 16279}]}'
    _default_test(
        'https://teszt.e-szigno.hu:440/tsa',
        username='teszt',
        password='teszt',
        certificate=os.path.join(os.path.dirname(__file__), '../data/e_szigno_test_tsa2.crt'),
        data=data,
        nonce=2,
        hashname='sha256',
    )


def test_encode_decode_timestamp_request():
    tsq = rfc3161ng.make_timestamp_request(data="test")
    pretty_print_str = "TimeStampReq:\n version=v1\n messageImprint=MessageImprint:\n  hashAlgorithm=AlgorithmIdentifier:\n   algorithm=1.3.14.3.2.26\n\n  hashedMessage=0xa94a8fe5ccb19ba61c4c0873d391e987982fbbd3\n\n certReq=False\n"
    # Some versions of prettyPrint() include quotes, others do not.
    # Hide the difference by removing the quotes.
    assert tsq.prettyPrint().replace("'", "") == pretty_print_str
    bin_tsq = rfc3161ng.encode_timestamp_request(tsq)
    assert bin_tsq == b'0$\x02\x01\x010\x1f0\x07\x06\x05+\x0e\x03\x02\x1a\x04\x14\xa9J\x8f\xe5\xcc\xb1\x9b\xa6\x1cL\x08s\xd3\x91\xe9\x87\x98/\xbb\xd3'
    tsq2 = rfc3161ng.decode_timestamp_request(bin_tsq)
    assert tsq2.getComponentByPosition(1).getComponentByPosition(1) == tsq.getComponentByPosition(1).getComponentByPosition(1)
    # This test is probably still incomplete


def test_generalized_time_decoding():
    from rfc3161ng.api import generalizedtime_to_utc_datetime

    # generalizedTime string, naive == expected datetime
    assert generalizedtime_to_utc_datetime('20180208181004,948468', True) == datetime.datetime(2018, 2, 8, 18, 10, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004', True) == datetime.datetime(2018, 2, 8, 18, 10, 4, 0)
    assert generalizedtime_to_utc_datetime('201802081810', True) == datetime.datetime(2018, 2, 8, 18, 10, 0, 0)
    assert generalizedtime_to_utc_datetime('2018020818', True) == datetime.datetime(2018, 2, 8, 18, 0, 0, 0)
    assert generalizedtime_to_utc_datetime('20180208181004.948468Z', True) == datetime.datetime(2018, 2, 8, 18, 10, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004.948468+01', True) == datetime.datetime(2018, 2, 8, 17, 10, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004.948468-01', True) == datetime.datetime(2018, 2, 8, 19, 10, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004.948468+0130', True) == datetime.datetime(2018, 2, 8, 16, 40, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004.948468Z', False) == datetime.datetime(2018, 2, 8, 18, 10, 4, 948468, tzinfo=dateutil.tz.tzutc())
    assert generalizedtime_to_utc_datetime('20180208181004.948468-01', False) == datetime.datetime(2018, 2, 8, 19, 10, 4, 948468, tzinfo=dateutil.tz.tzutc())
    assert generalizedtime_to_utc_datetime('20180208181004.948468+0130', False) == datetime.datetime(2018, 2, 8, 16, 40, 4, 948468, tzinfo=dateutil.tz.tzutc())

