use crate::crypto::{PublicKey};
use crate::data::{ByteSerial, SessionStatus, UserPassword};
use crate::error::{OneOfTo, WrapErrorOneOf};
use crate::proof::{DecryptedSession, EphemeralProofTokenState, InvalidEphemeral, InvalidProof, InvalidSession, SessionContent, UnknownTarget, UnvalidatedProofObject};
use crate::state::{CounterState, State};
use crate::store::{sessions, users, Store, StoreError};
use crate::{AppState, BytePacked, Claims, KeyState, Proof, Session};
use base64::{engine::general_purpose as b64, Engine as _};
use terrors::OneOf;

pub fn proof_token() {

}

pub fn decrypt_session(state: &impl State, session: &Session, time: u64) -> Result<DecryptedSession, OneOf<(StoreError, InvalidSession)>>{
    let keys = state.keys().sess_veri_keys();
    let store = state.store();
    let decrypted = session.decrypt(time, keys, |session| {
        sessions::session_status(store, session).to_one_of().map_err(OneOf::broaden)
    }, |e| {
        OneOf::new(e)
    })?;

    // let session_status = sessions::session_status(state.store(), session).to_one_of().map_err(OneOf::broaden)?;

    // session_status.valid(time).to_one_of().map_err(OneOf::broaden)?;

    // let session_keys = state.keys().sess_veri_keys();
    // let session = verify_session_bytes(session, session_keys).to_one_of().map_err(OneOf::broaden)?;

    Ok(decrypted)
}

pub fn verify_session<'a>(state: &impl State, session: &'a SessionContent<'a>, time: u64, max_age: Option<u64>) -> Result<(&'a BytePacked<Claims>, String), OneOf<(StoreError, InvalidSession)>>{
    let UserPassword { password_file, .. } =
        match users::get_login(state.store(),  &session.user_id)
            .to_one_of()
            .map_err(OneOf::broaden)?
        {
            Some(user) => user,
            None => {
                println!("User no longer exists!");
                return Err(OneOf::new(InvalidSession));
            }
        };
    
    let claims = match max_age {
        Some(max_age) => session.verify_max_age(time, &password_file, max_age),
        None => session.verify(time, &password_file),
    }
    .to_one_of().map_err(OneOf::broaden)?;

    Ok((claims, password_file))
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
    state: &impl State,
    proof: &'a Proof<T>,
    time: u64
) -> Result<UnvalidatedProofObject<'a, T, UnknownTarget>, OneOf<(InvalidProof,)>>
where
{
    let public_key = state.public_key();
    
    let proof_ob = proof.verify(public_key, time, |eph| {
        let keys = state.keys().eph_veri_keys(time);
        
        let decrypted_eph = eph.decrypt(&keys).map_err(|_| InvalidProof)?;
        let eph = decrypted_eph.read();
        eph.verify_state::<EphemeralProofTokenState, _>(time, |EphemeralProofTokenState { count, expires }| {
            if state.counter_used(eph.user_id, count, expires, time) {
                return Err(InvalidEphemeral)
            }
            
            Ok(())
        }).map_err(|_| InvalidProof)?;

        Ok(())
    }).to_one_of().map_err(OneOf::broaden)?;

    Ok(proof_ob)
}

#[cfg(feature = "test")]
pub mod test_util {
    use crate::data::SerializedAs;
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
