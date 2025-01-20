#![feature(type_changing_struct_update)]

use ed25519_dalek::{Signature, SigningKey, VerifyingKey, ed25519::signature::SignerMut};
use prost::Message;
use ed25519_dalek::Verifier;
use std::marker::PhantomData;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/authority_certificate.rs"));
}

/// A a certificate that whitelist a public key, to be valid it must contains the whitelisted public key signed by the certifier authority
/// and the resulting signature signed by the certified authority
pub struct AuthorityCertificate<CertifierSet, CertifiedSet, CertifierSignatureSet> {
    certifier_pubkey: Option<VerifyingKey>,
    certified_pubkey: Option<VerifyingKey>,
    certifier_signature: Option<Signature>,
    certified_signature: Option<Signature>,
    _certifier_set: PhantomData<CertifierSet>,
    _certified_set: PhantomData<CertifiedSet>,
    _certifier_signature_set: PhantomData<CertifierSignatureSet>,
    is_signed_by_certified: bool,
}

struct CertifierSet;
struct CertifiedSet;
struct CertifierSignatureSet;
struct NotSet;

impl Default for AuthorityCertificate<NotSet, NotSet, NotSet> {
    fn default() -> Self {
        AuthorityCertificate {
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

impl AuthorityCertificate<NotSet, NotSet, NotSet> {
    pub fn for_authority(
        self,
        certified_pubkey: VerifyingKey,
    ) -> AuthorityCertificate<CertifiedSet, NotSet, NotSet> {
        AuthorityCertificate {
            certified_pubkey: Some(certified_pubkey),
            _certifier_set: PhantomData,
            _certified_set: PhantomData,
            _certifier_signature_set: PhantomData,
            is_signed_by_certified: false,
            ..self
        }
    }
}

impl AuthorityCertificate<CertifiedSet, NotSet, NotSet> {
    pub fn from_certifier(
        self,
        certifier_signing_key: SigningKey,
    ) -> AuthorityCertificate<CertifiedSet, CertifierSet, CertifierSignatureSet> {
        let certifier_signature = self.certified_pubkey.as_ref().map(|certified_pubkey| {
            certifier_signing_key
                .clone()
                .sign(certified_pubkey.as_bytes())
        });
        AuthorityCertificate {
            certifier_pubkey: Some(certifier_signing_key.verifying_key()),
            certifier_signature,
            _certifier_set: PhantomData,
            _certified_set: PhantomData,
            _certifier_signature_set: PhantomData,
            ..self
        }
    }
}

impl AuthorityCertificate<CertifiedSet, CertifierSet, CertifierSignatureSet> {
    pub fn serialize_protobuf(&self) -> Vec<u8> {
        let cert = proto::AuthorityCertificate {
            certifier_pubkey: self.certifier_pubkey.unwrap().to_bytes().to_vec(),
            certified_pubkey: self.certified_pubkey.unwrap().to_bytes().to_vec(),
            certifier_signature: self.certifier_signature.unwrap().to_bytes().to_vec(),
            certified_signature: self.certified_signature.unwrap().to_bytes().to_vec(),
            is_signed_by_certified: self.is_signed_by_certified,
        };
        cert.encode_to_vec()
    }
}

impl AuthorityCertificate<CertifiedSet, CertifierSet, CertifierSignatureSet> {
    pub fn try_deserialize_protobuf(
        bytes: &[u8],
    ) -> anyhow::Result<AuthorityCertificate<CertifiedSet, CertifierSet, CertifierSignatureSet>>
    {
        let cert = proto::AuthorityCertificate::decode(bytes)?;
        Ok(AuthorityCertificate {
            certifier_pubkey: Some(VerifyingKey::try_from(cert.certifier_pubkey.as_slice())?),
            certified_pubkey: Some(VerifyingKey::try_from(cert.certified_pubkey.as_slice())?),
            certifier_signature: Some(Signature::try_from(cert.certifier_signature.as_slice())?),
            certified_signature: Some(Signature::try_from(cert.certified_signature.as_slice())?),
            is_signed_by_certified: cert.is_signed_by_certified,
            _certifier_set: PhantomData,
            _certified_set: PhantomData,
            _certifier_signature_set: PhantomData,
        })
    }
}

impl TryFrom<&[u8]> for AuthorityCertificate<CertifiedSet, CertifierSet, CertifierSignatureSet> {
    type Error = anyhow::Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        AuthorityCertificate::try_deserialize_protobuf(bytes)
    }
}

impl AuthorityCertificate<CertifiedSet, CertifierSet, CertifierSignatureSet> {
    pub fn sign_certified(self, certified_signing_key: SigningKey) -> Self {
        let signature = certified_signing_key.clone().sign(&self.certifier_signature.unwrap().to_vec());
        AuthorityCertificate {
            certified_signature: Some(signature),
            is_signed_by_certified: true,
            ..self
        }
    }
}

pub enum AuthorityCertificateError {
    NotSignedByCertified,
    InvalidCertifiedSignature,
    InvalidCertifierSignature,
}

impl AuthorityCertificate<CertifiedSet, CertifierSet, CertifierSignatureSet> {
    pub fn verify(&self, certified_pubkey: VerifyingKey) -> Result<(), Vec<AuthorityCertificateError>> {
        let mut errors = Vec::new();

        if let Err(_) = self.certifier_pubkey.unwrap().verify(self.certified_pubkey.unwrap().as_bytes(), &self.certifier_signature.unwrap()) {
            errors.push(AuthorityCertificateError::InvalidCertifierSignature);
        }
        if self.is_signed_by_certified {
            if let Err(_) = certified_pubkey.verify(self.certifier_signature.unwrap().to_vec().as_slice(), &self.certified_signature.unwrap()) {
                errors.push(AuthorityCertificateError::InvalidCertifiedSignature);
            }
        } else {
            errors.push(AuthorityCertificateError::NotSignedByCertified);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}