use frost_secp256k1_tr::*;
use k256::{elliptic_curve::bigint::Encoding, SecretKey};
use secp256k1::{schnorr, Secp256k1};
use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

#[test]
fn check_zero_key_fails() {
    frost_core::tests::ciphersuite_generic::check_zero_key_fails::<Secp256K1Sha256>();
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Secp256K1Sha256, _>(
        rng,
        b"message".into(),
    );
}

#[test]
fn check_dkg_part1_fails_with_invalid_signers_min_signers() {
    let rng = thread_rng();

    let min_signers = 1;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Secp256K1Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_dkg_part1_fails_with_min_signers_greater_than_max() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<Secp256K1Sha256> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Secp256K1Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_dkg_part1_fails_with_invalid_signers_max_signers() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 1;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Secp256K1Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_rts() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_rts::<Secp256K1Sha256, _>(rng);
}

#[test]
fn check_sign_with_dealer() {
    let mut rng = thread_rng();

    let msg = [1u8; 32];
    let merkle_root = vec![];

    let witness = SecretKey::random(&mut rng);
    let adaptor_point = witness.public_key();

    let (signing_target, signature, vk) = frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Secp256K1Sha256, _>(
        rng,
        SigningTarget::new(&msg, SigningParameters {
            tapscript_merkle_root: Some(merkle_root),
            adaptor_point: adaptor_point.to_sec1_bytes().to_vec(),
        }),
    );

    let R = signature.R();
    let s = signature.z();

    let adaptor_point = signing_target.sig_params().adaptor_point();
    let adapted_R = R + &adaptor_point;

    let witness = Secp256K1ScalarField::deserialize(&witness.as_scalar_primitive().as_uint().to_be_bytes()).unwrap();
    let adapted_s = if Secp256K1Group::y_is_odd(&adapted_R) {
        s - &witness
    } else {
        s + witness
    };

    let mut adapted_signature = [0u8; 64];
    adapted_signature[..32].copy_from_slice(&Secp256K1Group::serialize(&adapted_R)[1..]);
    adapted_signature[32..].copy_from_slice(&Secp256K1ScalarField::serialize(&adapted_s));

    let tweaked_pk = vk.effective_key(signing_target.sig_params()).serialize();
    let mut x_only_tweaked_pk = [0u8; 32];
    x_only_tweaked_pk.copy_from_slice(&tweaked_pk[1..]);

    let secp = Secp256k1::new();
    secp.verify_schnorr(&schnorr::Signature::from_byte_array(adapted_signature), signing_target.message(), &secp256k1::XOnlyPublicKey::from_byte_array(&x_only_tweaked_pk).unwrap()).unwrap()
}

#[test]
fn check_sign_with_dealer_fails_with_invalid_min_signers() {
    let rng = thread_rng();

    let min_signers = 1;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Secp256K1Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_sign_with_dealer_fails_with_min_signers_greater_than_max() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<Secp256K1Sha256> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Secp256K1Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_sign_with_dealer_fails_with_invalid_max_signers() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 1;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Secp256K1Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

/// This is testing that Shamir's secret sharing to compute and arbitrary
/// value is working.
#[test]
fn check_share_generation_secp256k1_tr_sha256() {
    let rng = thread_rng();
    frost_core::tests::ciphersuite_generic::check_share_generation::<Secp256K1Sha256, _>(rng);
}

#[test]
fn check_share_generation_fails_with_invalid_min_signers() {
    let rng = thread_rng();

    let min_signers = 0;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        Secp256K1Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_share_generation_fails_with_min_signers_greater_than_max() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<Secp256K1Sha256> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        Secp256K1Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_share_generation_fails_with_invalid_max_signers() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 0;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        Secp256K1Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

lazy_static! {
    pub static ref VECTORS: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors.json").trim())
            .expect("Test vector is valid JSON");
    pub static ref VECTORS_BIG_IDENTIFIER: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors-big-identifier.json").trim())
            .expect("Test vector is valid JSON");
    pub static ref VECTORS_DKG: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors_dkg.json").trim())
            .expect("Test vector is valid JSON");
}

#[test]
fn check_sign_with_test_vectors() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<Secp256K1Sha256>(&VECTORS);
}

#[test]
fn check_sign_with_test_vectors_dkg() {
    frost_core::tests::vectors_dkg::check_dkg_keygen::<Secp256K1Sha256>(&VECTORS_DKG);
}

#[test]
fn check_sign_with_test_vectors_with_big_identifiers() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<Secp256K1Sha256>(
        &VECTORS_BIG_IDENTIFIER,
    );
}

#[test]
fn check_error_culprit() {
    frost_core::tests::ciphersuite_generic::check_error_culprit::<Secp256K1Sha256>();
}

#[test]
fn check_identifier_derivation() {
    frost_core::tests::ciphersuite_generic::check_identifier_derivation::<Secp256K1Sha256>();
}

// Explicit test which is used in a documentation snippet
#[test]
#[allow(unused_variables)]
fn check_identifier_generation() -> Result<(), Error> {
    // ANCHOR: dkg_identifier
    let participant_identifier = Identifier::try_from(7u16)?;
    let participant_identifier = Identifier::derive("alice@example.com".as_bytes())?;
    // ANCHOR_END: dkg_identifier
    Ok(())
}

#[test]
fn check_sign_with_dealer_and_identifiers() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_and_identifiers::<
        Secp256K1Sha256,
        _,
    >(rng, b"message".into());
}

#[test]
fn check_sign_with_missing_identifier() {
    let rng = thread_rng();
    frost_core::tests::ciphersuite_generic::check_sign_with_missing_identifier::<Secp256K1Sha256, _>(
        rng,
    );
}

#[test]
fn check_sign_with_incorrect_commitments() {
    let rng = thread_rng();
    frost_core::tests::ciphersuite_generic::check_sign_with_incorrect_commitments::<
        Secp256K1Sha256,
        _,
    >(rng);
}
