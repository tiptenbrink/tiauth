use crate::crypto::{EphemeralKey, PublicKey};
use crate::data::{AboutVerify, ByteSerial, InvalidProof, ProofContent};
use crate::error::{OneOfTo, WrapErrorOneOf};
use crate::proof::{verify_proof_content, verify_session_bytes, EphemeralCounterState, InvalidEphemeral, InvalidSession, VerifiedSession};
use crate::state::{CounterState, State};
use crate::store::StoreError;
use crate::{AppState, Proof, Session};
use base64::{engine::general_purpose as b64, Engine as _};
use terrors::OneOf;

pub fn proof_token() {

}

// pub fn verify_proof_write<T: ByteSerial>(
//     state: &impl State,
//     write_txn: &WriteTransaction,
//     content: &mut ProofContent<T>,
// ) -> Result<(), OneOf<(DbError, InvalidProof)>> {
//     let tables = state.app_tables(&content.about.application);
//     let nonce = b64::URL_SAFE_NO_PAD.encode(&content.nonce);
//     let mut eph_table = write_txn.open_table(tables.ephemeral()).to_one_of_two()?;
//     {
//         // TODO clean up nonces every so often (after expiry)

//         let nonce_exists = eph_table.get(nonce.as_str()).to_one_of_two()?;

//         if nonce_exists.is_some() {
//             return Err(OneOf::new(InvalidProof {}));
//         }
//     }

//     let proof_expires = format!("{}", content.about.expires);
//     eph_table
//         .insert(nonce.as_str(), proof_expires.as_str())
//         .to_one_of_two()?;

//     Ok(())
// }

pub fn verify_proof<'a, T: ByteSerial>(
    state: &impl CounterState,
    proof: &'a Proof<T>,
    verify: AboutVerify,
    application: &str,
    public_key: &PublicKey,
    eph_keys: &[EphemeralKey],
    time: u64
) -> Result<ProofContent<'a, T>, OneOf<(StoreError, InvalidProof)>>
where
{
    let proof_content = verify_proof_content(proof, public_key, verify, time).map_err(OneOf::broaden)?;
    
    let proof_eph = proof_content.nonce.try_deserialize()
        .and_then(|v| v.verify(eph_keys, application))
        .map_err(|_| OneOf::new(InvalidProof {}))?;

    proof_eph.verify_state::<EphemeralCounterState, _>(|EphemeralCounterState { count, expires }| {
        if state.counter_used(proof_eph.user_id, count, expires, time) {
            return Err(InvalidEphemeral)
        }
        
        Ok(())
    }).map_err(|_| OneOf::new(InvalidProof {}))?;

    Ok(proof_content)
}

#[cfg(feature = "test")]
pub mod test_util {
    use crate::data::SerializedAs;
    use crate::data::{ActionType, Claims, Target, TargetList};
    use crate::proof::create_proof;
    use crate::state::{test_util::*, DriverState};

    use super::*;

    // pub fn create_proof_claims(
    //     state: &TestState,
    //     application: &str,
    //     user_id: &str,
    //     expires_in: Option<u64>,
    //     claims: impl SerializedAs<Claims>,
    // ) -> Proof<Claims> {
    //     let expires_in = expires_in.unwrap_or(1800);
    //     let key = state.private_key();

    //     create_proof(
    //         application,
    //         expires_in,
    //         ActionType::SetClaims,
    //         Target::Select,
    //         TargetList::user(user_id),
    //         claims,
    //         key,
    //         state.time()
    //     )
    // }
}

#[cfg(test)]
mod tests {
    use crate::{
        data::{ActionType, Claims, EXPIRE_TIME},
        proof::create_session,
        state::test_util::*, KeyState,
    };

    use test_util::*;

    use super::*;

    // #[test]
    // fn test_session_verify() {
    //     let user_id = "hi";
    //     let app = "abc";

    //     let state = TestState::setup_test(&app);

    //     let claims = Claims::new(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);

    //     let session = create_session(
    //         user_id,
    //         app,
    //         EXPIRE_TIME,
    //         claims.serialize(),
    //         &state.keys().session_key(),
    //     );

    //     let session = verify_session(&state.state, &session).unwrap();

    //     let session_read = session.read().unwrap();
    //     let session_claims = session_read.session_claims.deserialize();
    //     assert!(claims.eq_view(&session_claims));
    // }

    // #[test]
    // fn test_proof_verify() {
    //     let user_id = "hi";
    //     let app = "abc";

    //     let state = TestState::setup_test(&app);
    //     let claims = Claims::new(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);
    //     let proof = create_proof_claims(&state, app, user_id, None, claims.serialize());

    //     let proof_content =
    //         verify_proof(&state.state, &proof, AboutVerify::new(app, ActionType::SetClaims)).unwrap();

    //     let deser_claims = proof_content.data.deserialize();

    //     assert!(claims.eq_view(&deser_claims));
    //     assert_eq!(app, proof_content.about.application);
    // }
}
