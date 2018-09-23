import hashlib
import requests
import base64
import re
import datetime
import dateutil.relativedelta
import dateutil.tz

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import rfc3161ng

__all__ = (
    'RemoteTimestamper', 'check_timestamp', 'get_hash_oid',
    'TimestampingError', 'get_timestamp', 'make_timestamp_request',
    'encode_timestamp_request', 'encode_timestamp_response',
    'decode_timestamp_request', 'decode_timestamp_response',
)

id_attribute_messageDigest = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 4))


def get_hash_oid(hashname):
    return rfc3161ng.__dict__['id_' + hashname]


def get_hash_from_oid(oid):
    h = rfc3161ng.oid_to_hash.get(oid)
    if h is None:
        raise ValueError('unsupported hash algorithm', oid)
    return h


def get_hash_class_from_oid(oid):
    h = get_hash_from_oid(oid)
    return getattr(hashlib, h)


class TimestampingError(RuntimeError):
    pass


def generalizedtime_to_utc_datetime(gt, naive=True):
    m = re.match('(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?:(?P<minutes>\d{2})(?:(?P<seconds>\d{2})(?:[.,](?P<fractions>\d*))?)?)?(?P<tz>Z|[+-]\d{2}(?:\d{2})?)?', gt)
    if m:
        d = m.groupdict()
        dt = datetime.datetime(
            int(d['year']),
            int(d['month']),
            int(d['day']),
            int(d['hour']),
            int(d['minutes'] or 0),
            int(d['seconds'] or 0),
            int(float('0.' + d['fractions']) * 1000000 if d['fractions'] else 0)
        )
        if naive:
            if d['tz'] and d['tz'][0] in ('+', '-'):
                diff = dateutil.relativedelta.relativedelta(
                    hours=int(d['tz'][1:3]),
                    minutes=int(d['tz'][3:5]) if len(d['tz']) > 3 else 0
                )
                if d['tz'][0] == '+':
                    dt -= diff
                else:
                    dt += diff
            return dt
        else:
            if d['tz'] and re.match('^[+\-]\d*[^0]\d*$', d['tz']):
                diff = datetime.timedelta(
                    hours=int(d['tz'][1:3]),
                    minutes=int(d['tz'][3:5]) if len(d['tz']) > 3 else 0
                ).total_seconds()
                name = d['tz'][0:3]
                if len(d['tz']) > 3:
                    name += ':' + d['tz'][3:5]
                dt = dt.replace(tzinfo=dateutil.tz.tzoffset(name, diff if d['tz'][0] == '+' else -diff))
            else:
                dt = dt.replace(tzinfo=dateutil.tz.tzutc())
            return dt
    else:
        raise ValueError("not an ASN.1 generalizedTime: '%s'" % (gt,))


def get_timestamp(tst, naive=True):
    try:
        if not isinstance(tst, rfc3161ng.TimeStampToken):
            tst, substrate = decoder.decode(tst, asn1Spec=rfc3161ng.TimeStampToken())
            if substrate:
                raise ValueError("extra data after tst")

        tstinfo = tst.getComponentByName('content').getComponentByPosition(2).getComponentByPosition(1)
        tstinfo, substrate = decoder.decode(tstinfo, asn1Spec=univ.OctetString())
        if substrate:
            raise ValueError("extra data after tst")
        tstinfo, substrate = decoder.decode(tstinfo, asn1Spec=rfc3161ng.TSTInfo())
        if substrate:
            raise ValueError("extra data after tst")
        genTime = tstinfo.getComponentByName('genTime')
        return generalizedtime_to_utc_datetime(str(genTime), naive)
    except PyAsn1Error as exc:
        raise ValueError('not a valid TimeStampToken', exc)


def load_certificate(signed_data, certificate=b""):
    backend = default_backend()

    if certificate == b"":
        try:
            certificate = signed_data['certificates'][0][0]
        except (KeyError, IndexError, TypeError):
            raise AttributeError("missing certificate")
        data = encoder.encode(certificate)
        return x509.load_der_x509_certificate(data, backend)

    if b'-----BEGIN CERTIFICATE-----' in certificate:
        return x509.load_pem_x509_certificate(certificate, backend)
    return x509.load_der_x509_certificate(certificate, backend)


def check_timestamp(tst, certificate, data=None, digest=None, hashname=None, nonce=None):
    hashname = hashname or 'sha1'
    hashobj = hashlib.new(hashname)
    if digest is None:
        if not data:
            raise ValueError("check_timestamp requires data or digest argument")
        hashobj.update(data)
        digest = hashobj.digest()

    if not isinstance(tst, rfc3161ng.TimeStampToken):
        tst, substrate = decoder.decode(tst, asn1Spec=rfc3161ng.TimeStampToken())
        if substrate:
            raise ValueError("extra data after tst")
    signed_data = tst.content
    certificate = load_certificate(signed_data, certificate)
    if nonce is not None and int(tst.tst_info['nonce']) != int(nonce):
        raise ValueError('nonce is different or missing')
    # check message imprint with respect to locally computed digest
    message_imprint = tst.tst_info.message_imprint
    if message_imprint.hash_algorithm[0] != get_hash_oid(hashname) or bytes(message_imprint.hashed_message) != digest:
        raise ValueError('Message imprint mismatch')
    if not len(signed_data['signerInfos']):
        raise ValueError('No signature')
    # We validate only one signature
    signer_info = signed_data['signerInfos'][0]
    # check content type
    if tst.content['contentInfo']['contentType'] != rfc3161ng.id_ct_TSTInfo:
        raise ValueError("Signed content type is wrong: %s != %s" % (
            tst.content['contentInfo']['contentType'], rfc3161ng.id_ct_TSTInfo
        ))

    # check signed data digest
    content = bytes(decoder.decode(bytes(tst.content['contentInfo']['content']), asn1Spec=univ.OctetString())[0])
    # if there is authenticated attributes, they must contain the message
    # digest and they are the signed data otherwise the content is the
    # signed data
    if len(signer_info['authenticatedAttributes']):
        authenticated_attributes = signer_info['authenticatedAttributes']
        signer_digest_algorithm = signer_info['digestAlgorithm']['algorithm']
        signer_hash_class = get_hash_class_from_oid(signer_digest_algorithm)
        signer_hash_name = get_hash_from_oid(signer_digest_algorithm)
        content_digest = signer_hash_class(content).digest()
        for authenticated_attribute in authenticated_attributes:
            if authenticated_attribute[0] == id_attribute_messageDigest:
                try:
                    signed_digest = bytes(decoder.decode(bytes(authenticated_attribute[1][0]), asn1Spec=univ.OctetString())[0])
                    if signed_digest != content_digest:
                        raise ValueError('Content digest != signed digest')
                    s = univ.SetOf()
                    for i, x in enumerate(authenticated_attributes):
                        s.setComponentByPosition(i, x)
                    signed_data = encoder.encode(s)
                    break
                except PyAsn1Error:
                    raise
        else:
            raise ValueError('No signed digest')
    else:
        signed_data = content
    # check signature
    signature = signer_info['encryptedDigest']
    public_key = certificate.public_key()
    hash_family = getattr(hashes, signer_hash_name.upper())
    public_key.verify(
        bytes(signature),
        signed_data,
        padding.PKCS1v15(),
        hash_family(),
    )
    return True


class RemoteTimestamper(object):
    def __init__(self, url, certificate=None, capath=None, cafile=None, username=None, password=None, hashname=None, include_tsa_certificate=False, timeout=10):
        self.url = url
        self.certificate = certificate
        self.capath = capath
        self.cafile = cafile
        self.username = username
        self.password = password
        self.hashname = hashname or 'sha1'
        self.include_tsa_certificate = include_tsa_certificate
        self.timeout = timeout

    def check_response(self, response, digest, nonce=None):
        '''
           Check validity of a TimeStampResponse
        '''
        tst = response.time_stamp_token
        return self.check(tst, digest=digest, nonce=nonce)

    def check(self, tst, data=None, digest=None, nonce=None):
        return check_timestamp(
            tst,
            digest=digest,
            data=data,
            nonce=nonce,
            certificate=self.certificate,
            hashname=self.hashname,
        )

    def timestamp(self, data=None, digest=None, include_tsa_certificate=None, nonce=None):
        return self(
            data=data,
            digest=digest,
            include_tsa_certificate=include_tsa_certificate,
            nonce=nonce,
        )

    def __call__(self, data=None, digest=None, include_tsa_certificate=None, nonce=None, return_tsr=False):
        if data:
            digest = data_to_digest(data, self.hashname)

        request = make_timestamp_request(
            data=data,
            digest=digest,
            hashname=self.hashname,
            include_tsa_certificate=include_tsa_certificate if include_tsa_certificate is not None else self.include_tsa_certificate,
            nonce=nonce,
        )
        binary_request = encode_timestamp_request(request)

        headers = {'Content-Type': 'application/timestamp-query'}
        if self.username is not None:
            username = self.username.encode() if not isinstance(self.username, bytes) else self.username
            password = self.password.encode() if not isinstance(self.password, bytes) else self.password
            base64string = base64.standard_b64encode(b'%s:%s' % (username, password))
            if isinstance(base64string, bytes):
                base64string = base64string.decode()
            headers['Authorization'] = "Basic %s" % base64string
        try:
            response = requests.post(
                self.url,
                data=binary_request,
                timeout=self.timeout,
                headers=headers,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise TimestampingError('Unable to send the request to %r' % self.url, exc)
        tsr = decode_timestamp_response(response.content)
        self.check_response(tsr, digest, nonce=nonce)
        if return_tsr:
            return tsr
        return encoder.encode(tsr.time_stamp_token)


def data_to_digest(data, hashname='sha1'):
    hashobj = hashlib.new(hashname)
    if not isinstance(data, bytes):
        data = data.encode()
    hashobj.update(data)
    return hashobj.digest()


def make_timestamp_request(data=None, digest=None, hashname='sha1', include_tsa_certificate=False, nonce=None):
    algorithm_identifier = rfc2459.AlgorithmIdentifier()
    algorithm_identifier.setComponentByPosition(0, get_hash_oid(hashname))
    message_imprint = rfc3161ng.MessageImprint()
    message_imprint.setComponentByPosition(0, algorithm_identifier)
    hashobj = hashlib.new(hashname)
    if digest:
        assert len(digest) == hashobj.digest_size, 'digest length is wrong %s != %s' % (len(digest), hashobj.digest_size)
    elif data:
        digest = data_to_digest(data)
    else:
        raise ValueError('You must pass some data to digest, or the digest')
    message_imprint.setComponentByPosition(1, digest)
    tsq = rfc3161ng.TimeStampReq()
    tsq.setComponentByPosition(0, 'v1')
    tsq.setComponentByPosition(1, message_imprint)
    if nonce is not None:
        tsq.setComponentByPosition(3, int(nonce))
    tsq.setComponentByPosition(4, include_tsa_certificate)
    return tsq


def encode_timestamp_request(request):
    return encoder.encode(request)


def encode_timestamp_response(response):
    return encoder.encode(response)


def decode_timestamp_request(request):
    tsq, substrate = decoder.decode(request, asn1Spec=rfc3161ng.TimeStampReq())
    if substrate:
        raise ValueError('Extra data returned')
    return tsq


def decode_timestamp_response(response):
    tsr, substrate = decoder.decode(response, asn1Spec=rfc3161ng.TimeStampResp())
    if substrate:
        raise ValueError('Extra data returned')
    return tsr
