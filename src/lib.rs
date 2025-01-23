use ed25519_dalek::{Signature, SigningKey, VerifyingKey, ed25519::signature::SignerMut};
use prost::Message;
use ed25519_dalek::Verifier;
use std::marker::PhantomData;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/authority_certificate.rs"));
}

/// A a certificate that whitelist a public key, to be valid it must contains the whitelisted public key signed by the certifier authority
/// and the resulting signature signed by the certified authority
pub struct AuthorityCertificateBuilder<CertifierSet, CertifiedSet, CertifierSignatureSet> {
    certifier_pubkey: Option<VerifyingKey>,
    certified_pubkey: Option<VerifyingKey>,
    certifier_signature: Option<Signature>,
    certified_signature: Option<Signature>,
    _certifier_set: PhantomData<CertifierSet>,
    _certified_set: PhantomData<CertifiedSet>,
    _certifier_signature_set: PhantomData<CertifierSignatureSet>,
    is_signed_by_certified: bool,
}

pub struct AuthorityCertificate {
    certifier_pubkey: VerifyingKey,
    certified_pubkey: VerifyingKey,
    certifier_signature: Signature,
    certified_signature: Option<Signature>,
    is_signed_by_certified: bool,
}

struct CertifierSet;
struct CertifiedSet;
struct CertifierSignatureSet;
struct NotSet;

impl Default for AuthorityCertificateBuilder<NotSet, NotSet, NotSet> {
    fn default() -> Self {
        AuthorityCertificateBuilder {
            certifier_pubkey: None,
            certified_pubkey: None,
            certifier_signature: None,
            certified_signature: None,
            _certifier_set: PhantomData,
            _certified_set: PhantomData,
            _certifier_signature_set: PhantomData,
            is_signed_by_certified: false,
        }
    }
}

impl AuthorityCertificateBuilder<NotSet, NotSet, NotSet> {
    pub fn for_authority(
        self,
        certified_pubkey: VerifyingKey,
    ) -> AuthorityCertificateBuilder<CertifiedSet, NotSet, NotSet> {
        AuthorityCertificateBuilder {
            certified_pubkey: Some(certified_pubkey),
            _certifier_set: PhantomData,
            _certified_set: PhantomData,
            _certifier_signature_set: PhantomData,
            is_signed_by_certified: false,
            certifier_pubkey: self.certifier_pubkey,
            certifier_signature: self.certifier_signature,
            certified_signature: self.certified_signature,
        }
    }
}

impl AuthorityCertificateBuilder<CertifiedSet, NotSet, NotSet> {
    pub fn from_certifier(
        self,
        certifier_signing_key: SigningKey,
    ) -> AuthorityCertificateBuilder<CertifiedSet, CertifierSet, CertifierSignatureSet> {
        let certifier_signature = self.certified_pubkey.as_ref().map(|certified_pubkey| {
            certifier_signing_key
                .clone()
                .sign(certified_pubkey.as_bytes())
        });
        AuthorityCertificateBuilder {
            certifier_pubkey: Some(certifier_signing_key.verifying_key()),
            certifier_signature,
            _certifier_set: PhantomData,
            _certified_set: PhantomData,
            _certifier_signature_set: PhantomData,
            is_signed_by_certified: false,
            certified_pubkey: self.certified_pubkey,
            certified_signature: self.certified_signature,
        }
    }
}

impl AuthorityCertificate {
    pub fn serialize_protobuf(&self) -> Vec<u8> {
        let cert = proto::AuthorityCertificate {
            certifier_pubkey: self.certifier_pubkey.to_bytes().to_vec(),
            certified_pubkey: self.certified_pubkey.to_bytes().to_vec(),
            certifier_signature: self.certifier_signature.to_bytes().to_vec(),
            certified_signature: self.certified_signature.unwrap().to_bytes().to_vec(),
            is_signed_by_certified: self.is_signed_by_certified,
        };
        cert.encode_to_vec()
    }
}

impl AuthorityCertificate {
    pub fn try_deserialize_protobuf(
        bytes: &[u8],
    ) -> anyhow::Result<AuthorityCertificate>
    {
        let cert = proto::AuthorityCertificate::decode(bytes)?;
        Ok(AuthorityCertificate {
            certifier_pubkey: VerifyingKey::try_from(cert.certifier_pubkey.as_slice())?,
            certified_pubkey: VerifyingKey::try_from(cert.certified_pubkey.as_slice())?,
            certifier_signature: Signature::try_from(cert.certifier_signature.as_slice())?,
            certified_signature: Some(Signature::try_from(cert.certified_signature.as_slice())?),
            is_signed_by_certified: cert.is_signed_by_certified,
        })
    }
}

impl TryFrom<&[u8]> for AuthorityCertificate {
    type Error = anyhow::Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        AuthorityCertificate::try_deserialize_protobuf(bytes)
    }
}

impl AuthorityCertificate {
    pub fn sign_certified(self, certified_signing_key: SigningKey) -> Self {
        let signature = certified_signing_key.clone().sign(&self.certifier_signature.to_vec());
        AuthorityCertificate {
            certified_signature: Some(signature),
            is_signed_by_certified: true,
            ..self
        }
    }
}

pub enum AuthorityCertificateBuilderError {
    NotSignedByCertified,
    InvalidCertifiedSignature,
    InvalidCertifierSignature,
    InvalidCertifierPubkey,
    InvalidCertifiedPubkey,
}

impl AuthorityCertificate {
    pub fn verify(&self, certified_pubkey: VerifyingKey, certifier_pubkey: VerifyingKey) -> Result<(), Vec<AuthorityCertificateBuilderError>> {
        let mut errors = Vec::new();

        if let Err(_) = self.certifier_pubkey.verify(self.certified_pubkey.as_bytes(), &self.certifier_signature) {
            errors.push(AuthorityCertificateBuilderError::InvalidCertifierSignature);
        }
        if self.is_signed_by_certified {
            if let Err(_) = certified_pubkey.verify(self.certifier_signature.to_vec().as_slice(), &self.certified_signature.unwrap()) {
                errors.push(AuthorityCertificateBuilderError::InvalidCertifiedSignature);
            }
        } else {
            errors.push(AuthorityCertificateBuilderError::NotSignedByCertified);
        }
        if self.certifier_pubkey != certifier_pubkey {
            errors.push(AuthorityCertificateBuilderError::InvalidCertifierPubkey);
        }
        if self.certified_pubkey != certified_pubkey {
            errors.push(AuthorityCertificateBuilderError::InvalidCertifiedPubkey);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
