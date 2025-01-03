use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};

pub fn generate_self_signed() -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::default();
    params.not_before = date_time_ymd(1975, 1, 1);
    params.not_after = date_time_ymd(4096, 1, 1);
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "penumbra-x");
    distinguished_name.push(DnType::OrganizationName, "penumbra-x");
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into()?)];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert = cert.pem();
    tracing::info!("Generating self-signed certificate:\n{}", cert);

    Ok((cert.into_bytes(), key_pair.serialize_pem().into_bytes()))
}
