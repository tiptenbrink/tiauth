use std::borrow::Cow;
use std::collections::HashMap;

use base64::{engine::general_purpose as b64, Engine as _};
use lazy_borink::Lazy;
use pyo3::exceptions::PyValueError;
use pyo3::types::{PyBytes, PyDict, PyString};
use pyo3::{prelude::*, PyTypeInfo};
use tiauth_app::ProofBase;
use tiauth_core::api::Claims;

#[pymodule]
fn tiauth_app_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let internal = PyModule::new_bound(m.py(), "_internal")?;
    internal.add_function(wrap_pyfunction!(create_private_key_pem, &internal)?)?;
    internal.add_function(wrap_pyfunction!(public_from_private_key_pem, &internal)?)?;
    internal.add_function(wrap_pyfunction!(create_set_claims_proof, &internal)?)?;
    internal.add_function(wrap_pyfunction!(create_claims, &internal)?)?;
    internal.add_function(wrap_pyfunction!(create_reset_proof, &internal)?)?;
    internal.add_function(wrap_pyfunction!(create_read_all_proof, &internal)?)?;
    m.add_submodule(&internal)?;

    Ok(())
}

#[pyfunction]
fn create_private_key_pem() -> PyResult<String> {
    Ok(tiauth_app::create_private_key_pem())
}

#[pyfunction]
fn public_from_private_key_pem(private_key_pem: &str) -> PyResult<String> {
    Ok(tiauth_app::public_from_private_key_pem(private_key_pem))
}

struct LazyArg<T>(Lazy<T>);

trait FromPython {
    type PyType: PyTypeInfo;

    fn is_instance(ob: &Bound<'_, PyAny>) -> bool {
        ob.is_instance_of::<Self::PyType>()
    }

    fn extract_bound(ob: &Bound<'_, PyAny>) -> PyResult<Self>
    where
        Self: Sized;

    fn name() -> &'static str;
}

impl<'py, T> FromPyObject<'py> for LazyArg<T>
where
    T: FromPython,
{
    fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
        if T::is_instance(ob) {
            let inner = T::extract_bound(ob)?;
            Ok(LazyArg(Lazy::from_inner(inner)))
        } else if ob.is_instance_of::<PyBytes>() {
            let claim_bytes: Vec<u8> = ob.extract()?;
            return Ok(LazyArg(Lazy::from_bytes(claim_bytes)));
        } else if ob.is_instance_of::<PyString>() {
            let str: &str = ob.extract()?;
            let bytes = b64::URL_SAFE_NO_PAD
                .decode(str)
                .map_err(|_e| PyValueError::new_err("Failed to decode Python string as base64."))?;
            return Ok(LazyArg(Lazy::from_bytes(bytes)));
        } else {
            let msg = format!(
                "Unable to interpret {} type as {}!",
                ob.get_type().name()?,
                T::name()
            );
            Err(PyValueError::new_err(msg))
        }
    }
}

impl FromPython for Claims {
    type PyType = PyDict;

    fn name() -> &'static str {
        "Claims"
    }

    fn extract_bound(ob: &Bound<'_, PyAny>) -> PyResult<Self>
    where
        Self: Sized,
    {
        let dict = ob.downcast::<PyDict>()?;
        let mut map: HashMap<String, Vec<u8>> = HashMap::with_capacity(dict.len());

        dict.iter().try_for_each(|(k, v)| {
            let k: String = k.extract().map_err(|e| {
                let msg = format!("Failed to convert dictionary to claims map. Key '{}' is not a string: {}", k, e);
                PyValueError::new_err(msg)
            })?;
            let v: Vec<u8> = if v.is_instance_of::<PyString>() {
                let str_v: PyResult<String> = v.extract();
                str_v.map(|v| v.into_bytes())
            } else {
                v.extract()
            }.map_err(|e| {
                let msg = format!("Failed to convert dictionary to claims map. Value '{}' is not a string and could not be extracted as bytes: {}", v, e);
                PyValueError::new_err(msg)
            })?;

            map.insert(k, v);

            Ok::<(), PyErr>(())
        })?;

        Ok(Claims(map))
    }
}

#[pyfunction]
fn create_claims<'a>(claims: LazyArg<Claims>) -> PyResult<Cow<'a, [u8]>> {
    let claims = claims.0;

    Ok(Cow::from(claims.take_bytes()))
}

#[pyfunction]
fn create_set_claims_proof(
    application: &str,
    private_key_pem: &str,
    user_id: &str,
    claims: LazyArg<Claims>,
) -> PyResult<String> {
    let proof_base = ProofBase::new(application, private_key_pem);

    Ok(tiauth_app::create_set_claims_proof(
        proof_base, user_id, claims.0,
    ))
}

#[pyfunction]
fn create_reset_proof(application: &str, private_key_pem: &str, user_id: &str) -> PyResult<String> {
    let proof_base = ProofBase::new(application, private_key_pem);

    Ok(tiauth_app::create_reset_proof(proof_base, user_id))
}

#[pyfunction]
fn create_read_all_proof(application: &str, private_key_pem: &str) -> PyResult<String> {
    let proof_base = ProofBase::new(application, private_key_pem);

    Ok(tiauth_app::create_read_all_proof(proof_base))
}

// #[pyfunction]
// fn create_proof<'a>(
//     proof_use: &[u8], application: &str, private_key_pem: &str, expires_in: Option<u64>
// ) -> PyResult<Cow<'a, [u8]>> {
//     let proof_bytes = app::create_proof(proof_use, application, private_key_pem, expires_in);
//     //let bytes = PyBytes::new_bound(py, &proof_bytes);
//     Ok(Cow::from(proof_bytes))
// }
