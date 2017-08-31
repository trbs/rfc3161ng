import os.path
import datetime

# from pyasn1.type import univ

import rfc3161ng


def default_test(tsa_server, certificate, username=None, password=None, data='xx', nonce=None, **kwargs):
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


def test_time_certum_pl():
    default_test(
        'http://time.certum.pl',
        os.path.join(os.path.dirname(__file__), '../data/certum_certificate.crt'),
    )


def test_teszt_e_szigno_hu():
    data = '{"comment": "Envoi en Commission", "to": "Benjamin Dauvergne", "filetype": "Arr\u00eat CC", "from": "Benjamin Dauvergne", "files": [{"name": "affectations_ange1d.xlsx", "digest": "ce57e4ba353107dddaab91b9ad26c0569ffe0f94", "size": 16279}]}'
    default_test(
        'https://teszt.e-szigno.hu:440/tsa',
        username='teszt',
        password='teszt',
        certificate=os.path.join(os.path.dirname(__file__), '../data/e_szigno_test_tsa2.crt'),
        data=data,
        hashname='sha256',
    )


def test_teszt_e_szigno_hu_with_nonce():
    data = '{"comment": "Envoi en Commission", "to": "Benjamin Dauvergne", "filetype": "Arr\u00eat CC", "from": "Benjamin Dauvergne", "files": [{"name": "affectations_ange1d.xlsx", "digest": "ce57e4ba353107dddaab91b9ad26c0569ffe0f94", "size": 16279}]}'
    default_test(
        'https://teszt.e-szigno.hu:440/tsa',
        username='teszt',
        password='teszt',
        certificate=os.path.join(os.path.dirname(__file__), '../data/e_szigno_test_tsa2.crt'),
        data=data,
        nonce=2,
        hashname='sha256',
    )


def test_encode_decode_timestamp_request():
    tsr = rfc3161ng.make_timestamp_request(data="test")
    assert tsr.prettyPrint() == "TimeStampReq:\n version='v1'\n messageImprint=MessageImprint:\n  hashAlgorithm=AlgorithmIdentifier:\n   algorithm=1.3.14.3.2.26\n\n  hashedMessage=0xa94a8fe5ccb19ba61c4c0873d391e987982fbbd3\n\n certReq='False'\n"
    bin_tsr = rfc3161ng.encode_timestamp_request(tsr)
    assert bin_tsr == b'0$\x02\x01\x010\x1f0\x07\x06\x05+\x0e\x03\x02\x1a\x04\x14\xa9J\x8f\xe5\xcc\xb1\x9b\xa6\x1cL\x08s\xd3\x91\xe9\x87\x98/\xbb\xd3'
    tsr2 = rfc3161ng.decode_timestamp_request(bin_tsr)
    assert tsr2.getComponentByPosition(1).getComponentByPosition(1) == tsr.getComponentByPosition(1).getComponentByPosition(1)
    # This test is probably still incomplete
