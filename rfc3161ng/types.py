from pyasn1.type import univ, namedtype, tag, namedval, constraint, char, useful
from pyasn1_modules.rfc2459 import AlgorithmIdentifier, Extensions, MAX
from pyasn1_modules.rfc2315 import ContentInfo, signedData, SignedData
from pyasn1.codec.ber import decoder

__all__ = (
    'TimeStampReq', 'MessageImprint', 'PKIFreeText', 'PKIStatus', 'PKIFailureInfo',
    'PKIStatusInfo', 'TimeStampResp', 'Accuracy', 'AnotherName', 'GeneralName',
    'TimeStampToken', 'TSTInfo',
)


# Request

class TSAPolicyId(univ.ObjectIdentifier):
    pass


class MessageImprint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('hashedMessage', univ.OctetString()),
    )

    @property
    def hash_algorithm(self):
        return self[0]

    @property
    def hashed_message(self):
        return self[1]


class TimeStampReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(namedValues=namedval.NamedValues(('v1', 1)))),
        namedtype.NamedType('messageImprint', MessageImprint()),
        namedtype.OptionalNamedType('reqPolicy', TSAPolicyId()),
        namedtype.OptionalNamedType('nonce', univ.Integer()),
        namedtype.DefaultedNamedType('certReq', univ.Boolean(False)),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
    )


# Reponse

class PKIFreeText(univ.SequenceOf):
    componentType = char.UTF8String()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)


class PKIStatus(univ.Integer):
    namedValues = namedval.NamedValues(
        ('granted', 0),
        # -- when the PKIStatus contains the value zero a TimeStampToken, as
        #   requested, is present.
        ('grantedWithMods', 1),
        # -- when the PKIStatus contains the value one a TimeStampToken,
        #   with modifications, is present.
        ('rejection', 2),
        ('waiting', 3),
        ('revocationWarning', 4),
        # -- this message contains a warning that a revocation is
        # -- imminent
        ('revocationNotification', 5),
    )


class PKIFailureInfo(univ.BitString):
    namedValues = namedval.NamedValues(
        ('badAlg', 0),
        # -- unrecognized or unsupported Algorithm Identifier
        ('badRequest', 2),
        # -- transaction not permitted or supported
        ('badDataFormat', 5),
        # -- the data submitted has the wrong format
        ('timeNotAvailable', 14),
        # -- the TSA's time source is not available
        ('unacceptedPolicy', 15),
        # -- the requested TSA policy is not supported by the TSA
        ('unacceptedExtension', 16),
        # -- the requested extension is not supported by the TSA
        ('addInfoNotAvailable', 17),
        # -- the additional information requested could not be understood
        # -- or is not available
        ('systemFailure', 25),
        # -- the request cannot be handled due to system failure  }
    )


class PKIStatusInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('status', PKIStatus()),
        namedtype.OptionalNamedType('statusString', PKIFreeText()),
        namedtype.OptionalNamedType('failInfo', PKIFailureInfo()),
    )


class TimeStampToken(ContentInfo):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', signedData),
        namedtype.OptionalNamedType('content', SignedData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
    )

    @property
    def content(self):
        return self[1]

    @property
    def tst_info(self):
        x, substrate = decoder.decode(bytes(self.content['contentInfo']['content']))
        if substrate:
            raise ValueError('Incomplete decoding')
        x, substrate = decoder.decode(bytes(x), asn1Spec=TSTInfo())
        if substrate:
            raise ValueError('Incomplete decoding')
        return x


class TimeStampResp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('status', PKIStatusInfo()),
        namedtype.OptionalNamedType('timeStampToken', TimeStampToken())
    )

    @property
    def status(self):
        return self[0]

    @property
    def time_stamp_token(self):
        return self[1]


class Accuracy(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('seconds', univ.Integer()),
        namedtype.OptionalNamedType('millis', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('micros', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    )


# import from
class AnotherName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('type-id', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('value', univ.Any().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    )


class GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rfc822Name', char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        # namedtype.NamedType('dNSName', univ.Any().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        # namedtype.NamedType('x400Address', univ.Any().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.NamedType('directoryName', univ.Any().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
        # namedtype.NamedType('ediPartyName', univ.Any().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
        # namedtype.NamedType('uniformResourceIdentifier', char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
        # namedtype.NamedType('iPAddress', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.NamedType('registeredID', univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))))


class TSTInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(namedValues=namedval.NamedValues(('v1', 1)))),
        namedtype.OptionalNamedType('policy', TSAPolicyId()),
        namedtype.NamedType('messageImprint', MessageImprint()),
        # -- MUST have the same value as the similar field in
        # -- TimeStampReq
        namedtype.NamedType('serialNumber', univ.Integer()),
        # -- Time-Stamping users MUST be ready to accommodate integers
        # -- up to 160 bits.
        namedtype.NamedType('genTime', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('accuracy', Accuracy()),
        namedtype.DefaultedNamedType('ordering', univ.Boolean(False)),
        namedtype.OptionalNamedType('nonce', univ.Integer()),
        # -- MUST be present if the similar field was present
        # -- in TimeStampReq.  In that case it MUST have the same value.
        namedtype.OptionalNamedType('tsa', GeneralName().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    )

    @property
    def version(self):
        return self[0]

    @property
    def policy(self):
        return self[1]

    @property
    def message_imprint(self):
        return self[2]
