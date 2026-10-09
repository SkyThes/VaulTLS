use std::{cmp, env};
use std::net::IpAddr;
use anyhow::anyhow;
use anyhow::Result;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::{X509, X509Builder, X509NameBuilder, X509Req};
use openssl::x509::extension::{BasicConstraints as OpensslBasicConstraints, ExtendedKeyUsage as OpensslExtendedKeyUsage, SubjectAlternativeName as OpensslSubjectAlternativeName};
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, IsCa, KeyPair, KeyUsagePurpose, SerialNumber, SanType, BasicConstraints, CrlDistributionPoint};
use rustls_pki_types::CertificateDer;
use time::{OffsetDateTime, Duration};
use openssl::nid::Nid;
use rcgen::string::Ia5String;
use x509_parser::prelude::{parse_x509_pem, FromDer, X509Certificate};
use crate::data::enums::{CertData, CertificateRenewMethod, CertificateType, DataFormat, TimespanUnit};
use crate::data::enums::CertificateType::{TLSClient, TLSServer};
use crate::certs::common::{Certificate, CA};
use crate::data::enums::CAType::TLS;
use crate::data::objects::Name;

pub struct TLSCertificateBuilder {
    params: CertificateParams,
    key_pair: KeyPair,
    created_on: i64,
    valid_until: Option<i64>,
    name: Option<Name>,
    pkcs12_password: String,
    ca: Option<(i64, Vec<u8>, Vec<u8>)>,
    user_id: Option<i64>,
    renew_method: CertificateRenewMethod
}
impl TLSCertificateBuilder {
    pub fn new() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.not_before = OffsetDateTime::now_utc();
        params.serial_number = Some(SerialNumber::from(rand::random::<u64>()));

        let created_on_unix = params.not_before.unix_timestamp_nanos() / 1_000_000;

        Ok(Self {
            params,
            key_pair,
            created_on: created_on_unix as i64,
            valid_until: None,
            name: None,
            pkcs12_password: String::new(),
            ca: None,
            user_id: None,
            renew_method: Default::default()
        })
    }

    /// Copy information over from an existing certificate
    /// Fields set are:\
    ///     - Name\
    ///     - Validity\
    ///     - PKCS#12 Password\
    ///     - Renew Method\
    ///     - User ID\
    pub fn try_from(old_cert: &Certificate) -> Result<Self> {
        let validity_d = ((old_cert.valid_until - old_cert.created_on) / 1000 / 60 / 60 / 24).max(14);

        Self::new()?
            .set_name(old_cert.name.clone())?
            .set_valid_until(validity_d as u64, TimespanUnit::Day)?
            .set_password(&old_cert.password)?
            .set_renew_method(old_cert.renew_method)?
            .set_user_id(old_cert.user_id)
    }

    pub fn set_name(mut self, name: Name) -> Result<Self, anyhow::Error> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &name.cn);
        if let Some(ref ou) = name.ou {
            dn.push(DnType::OrganizationalUnitName, ou);
        }
        self.params.distinguished_name = dn;
        self.name = Some(name);
        Ok(self)
    }

    pub fn set_valid_until(mut self, duration: u64, unit: TimespanUnit) -> Result<Self, anyhow::Error> {
        let valid_until_time = get_timestamp(duration, unit);
        self.valid_until = Some(valid_until_time.unix_timestamp() * 1000);
        self.params.not_after = valid_until_time;
        Ok(self)
    }

    pub fn set_password(mut self, password: &str) -> Result<Self> {
        self.pkcs12_password = password.to_string();
        Ok(self)
    }

    /// Add Subject Alternative Names for a TLS server certificate.
    ///
    /// Every entry is auto-detected: if it parses as an IPv4/IPv6 address
    /// (optionally wrapped in `[]`), it becomes an `iPAddress` SAN, otherwise a
    /// `dNSName` SAN. Blank entries are ignored.
    pub fn set_dns_san(mut self, san_entries: &Vec<String>) -> Result<Self> {
        for entry in san_entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let san = match parse_san_ip(entry) {
                Some(ip) => SanType::IpAddress(ip),
                None => SanType::DnsName(Ia5String::try_from(entry.to_string())?),
            };
            self.params.subject_alt_names.push(san);
        }
        Ok(self)
    }

    pub fn set_email_san(mut self, email: &str) -> Result<Self> {
        self.params.subject_alt_names.push(SanType::Rfc822Name(Ia5String::try_from(email.to_string())?));
        Ok(self)
    }

    pub fn set_ca(mut self, ca: &CA) -> Result<Self, anyhow::Error> {
        if ca.ca_type != TLS {
            return Err(anyhow!("CA is not of type SSH"));
        }
        self.ca = Some((ca.id, ca.cert.clone(), ca.key.clone()));
        Ok(self)
    }

    pub fn set_user_id(mut self, user_id: i64) -> Result<Self, anyhow::Error> {
        self.user_id = Some(user_id);
        Ok(self)
    }

    pub fn set_renew_method(mut self, renew_method: CertificateRenewMethod) -> Result<Self, anyhow::Error> {
        self.renew_method = renew_method;
        Ok(self)
    }

    pub fn build_ca(mut self) -> Result<CA, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;

        self.params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        self.params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let cert = self.params.self_signed(&self.key_pair)?;

        Ok(CA{
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            ca_type: TLS,
            cert: cert.der().to_vec(),
            key: self.key_pair.serialize_der(),
            crl_number: 0,
        })
    }

    pub fn build_client(mut self) -> Result<Certificate, anyhow::Error> {
        self.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        self.build_common(TLSClient)
    }

    pub fn build_server(mut self) -> Result<Certificate, anyhow::Error> {
        self.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        self.build_common(TLSServer)
    }

    pub fn build_common(mut self, certificate_type: CertificateType) -> Result<Certificate, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;
        let user_id = self.user_id.ok_or(anyhow!("X509: user_id not set"))?;
        let (ca_id, ca_cert_der, ca_key_der) = self.ca.ok_or(anyhow!("X509: CA not set"))?;

        self.params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        self.params.is_ca = IsCa::ExplicitNoCa;

        if let Ok(crl_uri_base) = env::var("VAULTLS_CRL_DP_URL") {
            let crl_uri = format!("{}/crl/crl-{}.crl", crl_uri_base, ca_id);
            self.params.crl_distribution_points = vec![
                CrlDistributionPoint {
                    uris: vec![ crl_uri ],
                }
            ];
        }

        let ca_key_pair = KeyPair::try_from(ca_key_der.clone())?;
        let ca_cert_der_obj = CertificateDer::from(ca_cert_der.clone());
        let issuer = Issuer::from_ca_cert_der(&ca_cert_der_obj, ca_key_pair)?;

        let cert = self.params.signed_by(&self.key_pair, &issuer)?;
        let cert_der = cert.der().to_vec();

        // PKCS#12 creation using openssl (as rcgen doesn't support it)
        let openssl_cert = X509::from_der(&cert_der)?;
        let openssl_ca_cert = X509::from_der(&ca_cert_der)?;
        let openssl_pkey = PKey::private_key_from_der(&self.key_pair.serialize_der())?;

        let mut ca_stack = Stack::new()?;
        ca_stack.push(openssl_ca_cert)?;

        let pkcs12 = Pkcs12::builder()
            .name(&name.cn)
            .ca(ca_stack)
            .cert(&openssl_cert)
            .pkey(&openssl_pkey)
            .build2(&self.pkcs12_password)?;

        Ok(Certificate {
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            certificate_type,
            data: CertData::Pkcs12(pkcs12.to_der()?),
            password: self.pkcs12_password,
            ca_id,
            user_id,
            renew_method: self.renew_method,
            revoked_at: None
        })
    }
}

/// Issues a server certificate from a CSR and returns `(cert_pem, chain_pem, serial_bytes)`.
/// The CSR signature is verified before issuance. The subject CN is derived from the first DNS name.
pub fn issue_cert_from_csr(
    csr_der: &[u8],
    ca: &CA,
    validity_days: u64,
    dns_names: &[String],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let csr = X509Req::from_der(csr_der)?;
    let csr_pubkey = csr.public_key()?;
    if !csr.verify(&csr_pubkey)? {
        return Err(anyhow!("CSR signature verification failed"));
    }

    let ca_cert = X509::from_der(&ca.cert)?;
    let ca_key = PKey::private_key_from_der(&ca.key)?;

    let asn1_serial = generate_asn1_serial_number()?;
    let (_, not_before) = get_asn1_timestamp(0, TimespanUnit::Hour)?;
    let (_, not_after) = get_asn1_timestamp(validity_days, TimespanUnit::Day)?;

    let mut x509 = X509Builder::new()?;
    x509.set_version(2)?;
    x509.set_serial_number(&asn1_serial)?;
    x509.set_not_before(&not_before)?;
    x509.set_not_after(&not_after)?;
    x509.set_pubkey(&csr_pubkey)?;

    let cn = dns_names.first().map(|s| s.as_str()).unwrap_or("acme");
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", cn)?;
    name_builder.append_entry_by_text("OU", "ACME")?;
    x509.set_subject_name(&name_builder.build())?;

    if !dns_names.is_empty() {
        let mut san_builder = OpensslSubjectAlternativeName::new();
        for entry in dns_names {
            match parse_san_ip(entry) {
                Some(ip) => san_builder.ip(&ip.to_string()),
                None => san_builder.dns(entry),
            };
        }
        let san = san_builder.build(&x509.x509v3_context(None, None))?;
        x509.append_extension(san)?;
    }

    let ext_key_usage = OpensslExtendedKeyUsage::new().server_auth().build()?;
    x509.append_extension(ext_key_usage)?;

    let basic_constraints = OpensslBasicConstraints::new().build()?;
    x509.append_extension(basic_constraints)?;

    let key_usage = openssl::x509::extension::KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()?;
    x509.append_extension(key_usage)?;

    x509.set_issuer_name(ca_cert.subject_name())?;

    let subject_key_identifier = openssl::x509::extension::SubjectKeyIdentifier::new().build(&x509.x509v3_context(None, None))?;
    x509.append_extension(subject_key_identifier)?;

    let authority_key_identifier = openssl::x509::extension::AuthorityKeyIdentifier::new().keyid(true).build(&x509.x509v3_context(Some(&ca_cert), None))?;
    x509.append_extension(authority_key_identifier)?;

    x509.sign(&ca_key, MessageDigest::sha256())?;

    let cert = x509.build();

    let serial_bytes = cert.serial_number().to_bn()?.to_vec();
    let cert_pem = cert.to_pem()?;
    let ca_pem = ca_cert.to_pem()?;

    let mut chain_pem = cert_pem.clone();
    chain_pem.extend_from_slice(&ca_pem);

    Ok((cert_pem, chain_pem, serial_bytes))
}

fn generate_asn1_serial_number() -> Result<Asn1Integer> {
    let mut big_serial = BigNum::new()?;
    big_serial.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    let asn1_serial = big_serial.to_asn1_integer()?;
    Ok(asn1_serial)
}

fn get_asn1_timestamp(duration: u64, unit: TimespanUnit) -> Result<(i64, Asn1Time)> {
    let duration_per_unit_h = match unit {
        TimespanUnit::Year => 365*24,
        TimespanUnit::Month => 30*24,
        TimespanUnit::Day => 24,
        TimespanUnit::Hour => 1,
    };
    let duration_s = 60 * 60 * duration * duration_per_unit_h;
    let time = std::time::SystemTime::now() + std::time::Duration::from_secs(duration_s);
    let time_unix_ms = time.duration_since(std::time::UNIX_EPOCH)?.as_millis() as i64;
    let time_openssl = Asn1Time::from_unix(time_unix_ms / 1000)?;

    Ok((time_unix_ms, time_openssl))
}

pub(crate) fn get_timestamp(duration: u64, unit: TimespanUnit) -> OffsetDateTime {
    let duration_per_unit_h = match unit {
        TimespanUnit::Year => 365*24,
        TimespanUnit::Month => 30*24,
        TimespanUnit::Day => 24,
        TimespanUnit::Hour => 1,
    };
    let duration_s = cmp::max(duration * duration_per_unit_h, 1) * 60 * 60;
    OffsetDateTime::now_utc() + Duration::seconds(duration_s as i64)
}

/// Convert a CA certificate to PEM format.
pub(crate) fn get_tls_pem(ca: &CA) -> Result<Vec<u8>> {
    let cert = X509::from_der(&ca.cert)?;
    Ok(cert.to_pem()?)
}

pub(crate) fn extract_pem_serial_number(pem: &[u8]) -> Result<Vec<u8>> {
    let pem = parse_x509_pem(pem)
        .map_err(|e| anyhow!("Failed to parse PEM: {}", e))?;
    let (_, cert) = X509Certificate::from_der(&pem.1.contents)
        .map_err(|e| anyhow!("Failed to parse DER: {}", e))?;
    Ok(cert.tbs_certificate.serial.to_bytes_be())
}

pub(crate) fn extract_pkcs12_serial_number(pkcs12: &[u8], password: &str) -> Result<Vec<u8>> {
    let encrypted_p12 = Pkcs12::from_der(pkcs12)?;
    let parsed = encrypted_p12.parse2(password)?;
    let Some(inner) = parsed.cert else {
        return Err(anyhow!("No certificate found in PKCS#12"));
    };
    Ok(inner.serial_number().to_bn()?.to_vec())
}

/// Parse a SAN entry as an IP address. Accepts IPv4, IPv6 and bracketed IPv6 (`[::1]`).
/// Returns `None` if the entry is not an IP address (i.e. it should be treated as a DNS name).
pub(crate) fn parse_san_ip(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim();
    let entry = entry
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(entry);
    entry.parse::<IpAddr>().ok()
}

/// Collect the DNS and IP address SAN entries of an X509 certificate as strings.
fn san_entries(x509: &X509) -> Vec<String> {
    let Some(san) = x509.subject_alt_names() else { return vec![] };
    san.iter()
        .filter_map(|name| {
            if let Some(dns) = name.dnsname() {
                Some(dns.to_string())
            } else {
                name.ipaddress().and_then(|bytes| match bytes.len() {
                    4 => <[u8; 4]>::try_from(bytes).ok().map(|b| IpAddr::from(b).to_string()),
                    16 => <[u8; 16]>::try_from(bytes).ok().map(|b| IpAddr::from(b).to_string()),
                    _ => None,
                })
            }
        })
        .collect()
}

/// Extract the DNS names and IP addresses stored in the SAN of an X509 certificate.
/// (The name is kept for compatibility; IP SAN entries are returned as well so a renewal keeps them.)
pub(crate) fn get_dns_names(cert: &Certificate) -> Result<Vec<String>, anyhow::Error> {
    match &cert.data {
        CertData::Pem(bytes) => {
            let x509 = X509::from_pem(bytes)?;
            Ok(san_entries(&x509))
        }
        CertData::Pkcs12(bytes) => {
            let encrypted_p12 = Pkcs12::from_der(bytes)?;
            let Some(inner) = encrypted_p12.parse2(&cert.password)?.cert else {
                return Err(anyhow!("No certificate found in PKCS#12"));
            };
            if inner.subject_alt_names().is_none() {
                return Err(anyhow!("No SAN found in PKCS#12 certificate"));
            }
            Ok(san_entries(&inner))
        }
        CertData::SshBundle(_) => Ok(vec![]),
    }
}

pub fn parse_ca(cert_bytes: &[u8], key_bytes: &[u8], data_format: DataFormat, crl_number: i64) -> Result<CA> {
    use x509_parser::prelude::FromDer;
    let (cert_der, key_der) = match data_format {
        DataFormat::DER => (cert_bytes.to_vec(), key_bytes.to_vec()),
        DataFormat::PEM => {
            let cert_pem = parse_x509_pem(cert_bytes)
                .map_err(|e| anyhow!("Failed to parse CA Cert PEM: {}", e))?;

            let key_pem = parse_x509_pem(key_bytes)
                .map_err(|e| anyhow!("Failed to parse CA Private Key PEM: {}", e))?;

            (cert_pem.1.contents, key_pem.1.contents)
        }
    };

    let (_, cert) = X509Certificate::from_der(&cert_der)
        .map_err(|e| anyhow!("Failed to parse CA DER: {}", e))?;

    let subject = &cert.tbs_certificate.subject;
    let cn = subject.iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .ok_or_else(|| anyhow!("No CN in CA certificate"))?
        .to_string();

    let ou = subject.iter_organizational_unit()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string());
    
    let created_on_unix = cert.tbs_certificate.validity.not_before.timestamp() * 1000;
    let valid_until_unix = cert.tbs_certificate.validity.not_after.timestamp() * 1000;

    Ok(CA {
        id: -1,
        name: Name { cn, ou },
        created_on: created_on_unix,
        valid_until: valid_until_unix,
        ca_type: TLS,
        cert: cert_der,
        key: key_der,
        crl_number,
    })
}

pub fn parse_p12_metadata(p12_bytes: &[u8], password: &str) -> Result<(Name, i64, i64)> {
    let p12 = Pkcs12::from_der(p12_bytes)?;
    let parsed = p12.parse2(password)?;
    let cert = parsed.cert.ok_or_else(|| anyhow!("No certificate in PKCS#12"))?;
    
    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(Nid::COMMONNAME)
        .next()
        .ok_or_else(|| anyhow!("No CN in certificate"))?
        .data()
        .to_string()?;

    let ou = subject.entries_by_nid(Nid::ORGANIZATIONALUNITNAME)
        .next()
        .and_then(|e| e.data().to_string().ok());

    let created_on_unix = asn1_time_to_unix(cert.not_before())?;
    let valid_until_unix = asn1_time_to_unix(cert.not_after())?;

    Ok((Name { cn, ou }, created_on_unix, valid_until_unix))
}

fn asn1_time_to_unix(time: &openssl::asn1::Asn1TimeRef) -> Result<i64> {
    let epoch = Asn1Time::from_unix(0)?;
    let diff = epoch.diff(time)?;
    Ok((diff.days as i64 * 24 * 3600 + diff.secs as i64) * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_san_ip_detects_addresses() {
        assert_eq!(parse_san_ip("192.168.1.1"), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(parse_san_ip(" 10.0.0.1 "), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(parse_san_ip("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_san_ip("[::1]"), Some("::1".parse().unwrap()));
        assert_eq!(parse_san_ip("router.home.lan"), None);
        assert_eq!(parse_san_ip("999.1.1.1"), None);
        assert_eq!(parse_san_ip("1.2.3"), None);
    }

    fn test_ca() -> CA {
        TLSCertificateBuilder::new().unwrap()
            .set_name(Name { cn: "Test CA".to_string(), ou: None }).unwrap()
            .set_valid_until(1, TimespanUnit::Year).unwrap()
            .build_ca().unwrap()
    }

    #[test]
    fn server_cert_contains_dns_and_ip_sans() {
        let ca = test_ca();
        let entries = vec![
            "router.home.lan".to_string(),
            "192.168.1.1".to_string(),
            "[2001:db8::1]".to_string(),
            "   ".to_string(),
        ];
        let cert = TLSCertificateBuilder::new().unwrap()
            .set_name(Name { cn: "router.home.lan".to_string(), ou: None }).unwrap()
            .set_valid_until(1, TimespanUnit::Year).unwrap()
            .set_ca(&ca).unwrap()
            .set_user_id(1).unwrap()
            .set_dns_san(&entries).unwrap()
            .build_server().unwrap();

        let CertData::Pkcs12(ref der) = cert.data else { panic!("expected PKCS#12") };
        let p12 = Pkcs12::from_der(der).unwrap().parse2("").unwrap();
        let x509 = p12.cert.unwrap();
        let san = x509.subject_alt_names().unwrap();

        let dns: Vec<_> = san.iter().filter_map(|n| n.dnsname().map(str::to_string)).collect();
        assert_eq!(dns, vec!["router.home.lan".to_string()]);

        let ips: Vec<_> = san.iter().filter_map(|n| n.ipaddress().map(|b| b.to_vec())).collect();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&vec![192, 168, 1, 1]));
        assert!(ips.contains(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec()));

        // Renewal path: the IP SANs must survive get_dns_names -> set_dns_san
        let extracted = get_dns_names(&cert).unwrap();
        assert_eq!(extracted.len(), 3);
        assert!(extracted.contains(&"router.home.lan".to_string()));
        assert!(extracted.contains(&"192.168.1.1".to_string()));
        assert!(extracted.contains(&"2001:db8::1".to_string()));
    }

    #[test]
    fn csr_issuance_supports_ip_sans() {
        let ca = test_ca();
        let key = PKey::from_ec_key(
            openssl::ec::EcKey::generate(
                &openssl::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()
            ).unwrap()
        ).unwrap();
        let mut req = openssl::x509::X509ReqBuilder::new().unwrap();
        req.set_pubkey(&key).unwrap();
        req.sign(&key, MessageDigest::sha256()).unwrap();
        let csr_der = req.build().to_der().unwrap();

        let names = vec!["nas.home.lan".to_string(), "10.1.2.3".to_string()];
        let (cert_pem, _, _) = issue_cert_from_csr(&csr_der, &ca, 30, &names).unwrap();
        let x509 = X509::from_pem(&cert_pem).unwrap();
        let san = x509.subject_alt_names().unwrap();
        assert!(san.iter().any(|n| n.dnsname() == Some("nas.home.lan")));
        assert!(san.iter().any(|n| n.ipaddress() == Some(&[10, 1, 2, 3][..])));
    }
}
