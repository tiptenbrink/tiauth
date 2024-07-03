use std::cmp::Ordering;
use std::collections::HashMap;
use std::ops::Deref;

use base64::{engine::general_purpose as b64, Engine as _};
// use lazy_borink::lib2::LazyPack;
use pyo3::exceptions::PyValueError;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyBytes, PyDict, PyString};
use pyo3::{prelude::*, PyTypeInfo};
use tiauth_core::{app, ByteOwned, BytePacked, ByteSerial};
use tiauth_core::app::ProofBaseView;
use tiauth_core::crypto::{load_key, Key};
use tiauth_core::Claims;

#[pyclass(frozen)]
struct ProofKey {
    key: Key,
}



#[pyfunction]
fn create_key(private_key_pem: &str) -> PyResult<ProofKey> {
    let key = load_key(private_key_pem)
        .map_err(|_| PyValueError::new_err("Could not parse PEM file as Ed25519 private key."))?;

    Ok(ProofKey { key })
}

#[pymodule]
fn tiauth_app_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let internal = PyModule::new_bound(m.py(), "_internal")?;
    internal.add_function(wrap_pyfunction!(create_private_key_pem, &internal)?)?;
    internal.add_function(wrap_pyfunction!(public_from_private_key_pem, &internal)?)?;
    internal.add_function(wrap_pyfunction!(create_set_claims_proof, &internal)?)?;
    internal.add_function(wrap_pyfunction!(create_reset_proof, &internal)?)?;
    internal.add_function(wrap_pyfunction!(create_read_all_proof, &internal)?)?;
    internal.add_function(wrap_pyfunction!(create_key, &internal)?)?;
    m.add_submodule(&internal)?;

    Ok(())
}

#[pyfunction]
fn create_private_key_pem() -> PyResult<String> {
    Ok(app::create_private_key_pem())
}

#[pyfunction]
fn public_from_private_key_pem(private_key_pem: &str) -> PyResult<String> {
    app::public_from_private_key_pem(private_key_pem)
        .map_err(|_| PyValueError::new_err("Could not parse PEM file as Ed25519 private key."))
}

// struct LazyArg<T>(Lazy<T>);

// trait FromPython {
//     type PyType: PyTypeInfo;

//     fn is_instance(ob: &Bound<'_, PyAny>) -> bool {
//         ob.is_instance_of::<Self::PyType>()
//     }

//     fn extract_bound(ob: &Bound<'_, PyAny>) -> PyResult<Self>
//     where
//         Self: Sized;

//     fn name() -> &'static str;
// }

// impl<'py, T> FromPyObject<'py> for LazyArg<T>
// where
//     T: FromPython,
// {
//     fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
//         // Extracting from T is the slow part
//         if ob.is_instance_of::<PyBytes>() {
//             let claim_bytes: Vec<u8> = ob.extract()?;
//             Ok(LazyArg(Lazy::from_bytes(claim_bytes)))
//         } else if ob.is_instance_of::<PyString>() {
//             let str: &str = ob.extract()?;
//             let bytes = b64::URL_SAFE_NO_PAD
//                 .decode(str)
//                 .map_err(|_e| PyValueError::new_err("Failed to decode Python string as base64."))?;
//             return Ok(LazyArg(Lazy::from_bytes(bytes)));
//         } else if T::is_instance(ob) {
//             let inner = T::extract_bound(ob)?;
//             Ok(LazyArg(Lazy::from_inner(inner)))
//         } else {
//             let msg = format!(
//                 "Unable to interpret {} type as {}!",
//                 ob.get_type().name()?,
//                 T::name()
//             );
//             Err(PyValueError::new_err(msg))
//         }
//     }
// }

// impl FromPython for Claims {
//     type PyType = PyDict;

//     fn name() -> &'static str {
//         "Claims"
//     }

//     fn extract_bound(ob: &Bound<'_, PyAny>) -> PyResult<Self>
//     where
//         Self: Sized,
//     {
//         let dict = ob.downcast::<PyDict>()?;
//         let mut map: HashMap<String, Vec<u8>> = HashMap::with_capacity(dict.len());
//         // Iterating over the dict is the slow part
//         dict.iter().try_for_each(|(k, v)| {
//             let k: String = k.extract().map_err(|e| {
//                 let msg = format!("Failed to convert dictionary to claims map. Key '{}' is not a string: {}", k, e);
//                 PyValueError::new_err(msg)
//             })?;
//             let v: Vec<u8> = if v.is_instance_of::<PyString>() {
//                 let str_v: PyResult<String> = v.extract();
//                 str_v.map(|v| v.into_bytes())
//             } else {
//                 v.extract()
//             }.map_err(|e| {
//                 let msg = format!("Failed to convert dictionary to claims map. Value '{}' is not a string and could not be extracted as bytes: {}", v, e);
//                 PyValueError::new_err(msg)
//             })?;

//             map.insert(k, v);

//             Ok::<(), PyErr>(())
//         })?;

//         Ok(Claims(map))
//     }
// }

impl<'py> FromPyObject<'py> for ClaimsSerialized {
    fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
        if ob.is_instance_of::<PyBytes>() {
            let claim_bytes = ob.downcast::<PyBytes>().unwrap();
            Ok(ClaimsSerialized::PyBytes(claim_bytes.clone().into()))
        } else if ob.is_instance_of::<PyDict>() {
            let claim_dict = ob.downcast::<PyDict>().unwrap();
            let mut keys: Vec<String> = Vec::with_capacity(claim_dict.len());
            let mut values: Vec<Vec<u8>> = Vec::with_capacity(claim_dict.len());

            let mut i = 0;
            for (k, v) in claim_dict.into_iter() {
                let key: String = k.extract().map_err(|e| {
                    let msg = format!("Failed to convert dictionary to claims map. Key '{}' is not a string: {}", k, e);
                    PyValueError::new_err(msg)
                })?;

                if i != 0 {
                    let k_prev = &keys[i-1];
                    if let Ordering::Greater = k_prev.cmp(&key) {
                        return Err(PyValueError::new_err("Claim keys are not sorted in ascending order!"))
                    }
                }
                i += 1;

                let value: Vec<u8> = if v.is_instance_of::<PyString>() {
                    let str_v: PyResult<String> = v.extract();
                    str_v.map(|v| v.into_bytes())
                } else {
                    v.extract()
                }.map_err(|e| {
                    let msg = format!("Failed to convert dictionary to claims map. Value '{}' is not a string and could not be extracted as bytes: {}", v, e);
                    PyValueError::new_err(msg)
                })?;
                
                keys.push(key);
                values.push(value);
            }

            let serialized = Claims::from_keys_values(keys, values).serialize();

            Ok(ClaimsSerialized::Serialized(serialized))
        } else {
            let msg = format!(
                "Unable to interpret {} type as claims, provide either a dict[str, str | bytes] or bytes!",
                ob.get_type().name()?
            );
            Err(PyValueError::new_err(msg))
        }
    }
}

enum ClaimsSerialized {
    Serialized(ByteOwned<Claims>),
    PyBytes(PyBackedBytes)
}

impl ClaimsSerialized {
    fn as_bytes(&self) -> &BytePacked<Claims> {
        match &self {
            Self::PyBytes(bytes) => BytePacked::new(bytes.deref()),
            Self::Serialized(byte_owned) => byte_owned.as_packed()
        }
    }
}

#[pyfunction]
fn create_set_claims_proof<'py>(
    py: Python<'py>,
    application: &str,
    key: &Bound<'_, ProofKey>,
    user_id: &str,
    claims: ClaimsSerialized,
) -> PyResult<String> {
    let key = &key.get().key;
    // The claim bytes are immutable, so we can use them even from outside the GIL, 
    let proof = py.allow_threads(|| {
        let proof_base = ProofBaseView::new(application, key);
        app::create_set_claims_proof(proof_base, user_id, claims.as_bytes())
    });

    Ok(proof)
}

#[pyfunction]
fn create_reset_proof(
    application: &str,
    key: &Bound<'_, ProofKey>,
    user_id: &str,
) -> PyResult<String> {
    let proof_base = ProofBaseView::new(application, &key.get().key);

    Ok(app::create_reset_proof(proof_base, user_id))
}

#[pyfunction]
fn create_read_all_proof(application: &str, key: &Bound<'_, ProofKey>) -> PyResult<String> {
    let proof_base = ProofBaseView::new(application, &key.get().key);

    Ok(app::create_read_all_proof(proof_base))
}

// #[pyfunction]
// fn create_proof<'a>(
//     proof_use: &[u8], application: &str, private_key_pem: &str, expires_in: Option<u64>
// ) -> PyResult<Cow<'a, [u8]>> {
//     let proof_bytes = app::create_proof(proof_use, application, private_key_pem, expires_in);
//     //let bytes = PyBytes::new_bound(py, &proof_bytes);
//     Ok(Cow::from(proof_bytes))
// }
