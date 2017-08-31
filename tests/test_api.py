import os.path
import datetime

from pyasn1.type import univ

import rfc3161


def default_test(tsa_server, certificate, username=None, password=None, data='xx', nonce=None, **kwargs):
    kwargs.update({
            'certificate': file(certificate).read()
    })
    if username and password:
        kwargs.update({
            'username': username,
            'password': password,
        })

    timestamper = rfc3161.RemoteTimestamper(tsa_server, **kwargs)
    kwargs = {}
    if nonce:
        kwargs['nonce'] = nonce
    value, substrate = timestamper(data=data, **kwargs)
    assert not value is False, substrate
    assert isinstance(rfc3161.get_timestamp(value), datetime.datetime)
    assert not value is None
    assert substrate == ''


def test_time_certum_pl():
    default_test('http://time.certum.pl',
            os.path.join(os.path.dirname(__file__),
                '../data/certum_certificate.crt'))


def test_teszt_e_szigno_hu():
    data = '{"comment": "Envoi en Commission", "to": "Benjamin Dauvergne", "filetype": "Arr\u00eat CC", "from": "Benjamin Dauvergne", "files": [{"name": "affectations_ange1d.xlsx", "digest": "ce57e4ba353107dddaab91b9ad26c0569ffe0f94", "size": 16279}]}'
    default_test('https://teszt.e-szigno.hu:440/tsa',
            username='teszt', password='teszt',
            certificate=os.path.join(os.path.dirname(__file__),
                '../data/e_szigno_test_tsa2.crt'),
            data=data, hashname='sha256')


def test_teszt_e_szigno_hu_with_nonce():
    data = '{"comment": "Envoi en Commission", "to": "Benjamin Dauvergne", "filetype": "Arr\u00eat CC", "from": "Benjamin Dauvergne", "files": [{"name": "affectations_ange1d.xlsx", "digest": "ce57e4ba353107dddaab91b9ad26c0569ffe0f94", "size": 16279}]}'
    default_test('https://teszt.e-szigno.hu:440/tsa',
            username='teszt', password='teszt',
            certificate=os.path.join(os.path.dirname(__file__),
                '../data/e_szigno_test_tsa2.crt'),
            data=data, nonce=2, hashname='sha256')
