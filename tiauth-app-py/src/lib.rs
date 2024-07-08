use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyBytes, PyDict, PyString};
use tiauth_core::encoded::Encodable;
use std::cmp::Ordering;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use tiauth_core::app::ProofBaseView;
use tiauth_core::crypto::{load_key, Key};
use tiauth_core::Claims;
use tiauth_core::{app, ByteOwned, BytePacked, ByteSerial};

#[pyclass(frozen)]
struct ProofKey {
    key: Key,
}

#[pyclass(frozen)]
struct AppClient {
    inner: Arc<tiauth_app::AppClient>
}


#[pyclass(frozen)]
pub struct ApplicationLogin {
    inner: Arc<tiauth_app::ApplicationLogin>
}


#[pyclass(frozen)]
pub struct ApplicationRegister {
    // We use an Mutex<Option<T>> to ensure it is used once while avoiding the need to copy the proof, which can be quite large
    inner: Arc<Mutex<Option<tiauth_app::ApplicationRegister>>>
}

#[pymethods]
impl AppClient {
    #[new]
    #[pyo3(signature = (application, private_key_pem, proof_expiration=None))]
    fn new(application: &str, private_key_pem: &str, proof_expiration: Option<u64>) -> Self {
        let inner = Arc::new(tiauth_app::AppClient::new(application, private_key_pem, proof_expiration));

        Self {
            inner
        }
    }

    #[pyo3(signature = (user_id, all_claims=None, requested_claims=None))]
    pub fn prepare_login(&self, user_id: &str, all_claims: Option<bool>, requested_claims: Option<Vec<String>>) -> ApplicationLogin {
        let inner = self.inner.prepare_login(user_id, all_claims, requested_claims);

        ApplicationLogin {
            inner: Arc::new(inner)
        }
    }

    #[pyo3(signature = (user_id, set_claims=None))]
    pub fn prepare_register(&self, user_id: &str, set_claims: Option<ClaimsSerialized>) -> ApplicationRegister {
        let set_claims = set_claims.as_ref().map(|c| c.as_bytes());

        let inner = self.inner.prepare_register(user_id, set_claims);

        ApplicationRegister {
            inner: Arc::new(Mutex::new(Some(inner)))
        }
    }
}

#[pyclass(frozen)]
struct UserClient {
    inner: Arc<tiauth_app::UserClient>
}

#[pymethods]
impl UserClient {
    #[new]
    fn new(application: &str, tiauth_url: &str) -> Self {
        let inner = Arc::new(tiauth_app::UserClient::new(application, tiauth_url));

        Self {
            inner
        }
    }

    /// The ApplicationRegister can be quite big as it can contain all claim values. For now we only have an Encoded type
    /// that must own its data to be encoded, but we can create a new type in the future that contains a reference that can
    /// be encoded and serialized from a reference.
    /// So until then we want to have the owned value without cloning, so we must consume the given value. This is done by
    /// taking it out of an Option inside a Mutex. You cannot reuse the ApplicationRegister.
    pub fn register_user(&self, app_register: &ApplicationRegister, password: &str) -> PyResult<()> {
        let app_register = {
            // We use a scope to ensure the Mutex is dropped before we call unwrap below
            app_register.inner.lock().unwrap().take().ok_or_else(|| {
                PyValueError::new_err("ApplicationRegister can only be used once! Create a new value and do not reuse it.")
            })?
        };

        self.inner.register_user_blocking(app_register, password).unwrap();

        Ok(())
    }

    pub fn login_user(&self, app_login: &ApplicationLogin, password: &str) -> String {
        // ApplicationLogin is likely not very larg so we are fine with just cloning
        // Note that in cases of a very large amount of requested claims it can still be big
        let app_login = app_login.inner.as_ref().clone();

        self.inner.login_user_blocking(app_login, password).unwrap()
    }
}

#[pyfunction]
fn load_key_from_pem(private_key_pem: &str) -> PyResult<ProofKey> {
    let key = load_key(private_key_pem)
        .map_err(|_| PyValueError::new_err("Could not parse PEM file as Ed25519 private key."))?;

    Ok(ProofKey { key })
}

#[pymodule]
fn _internal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // let internal = PyModule::new_bound(m.py(), "_internal")?;
    m.add_function(wrap_pyfunction!(create_private_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(public_from_private_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(create_set_claims_proof, m)?)?;
    m.add_function(wrap_pyfunction!(create_reset_proof, m)?)?;
    m.add_function(wrap_pyfunction!(create_read_all_proof, m)?)?;
    m.add_function(wrap_pyfunction!(load_key_from_pem, m)?)?;
    m.add_function(wrap_pyfunction!(create_read_some_proof, m)?)?;
    m.add_function(wrap_pyfunction!(create_read_range_proof, m)?)?;
    m.add_class::<ProofKey>()?;
    m.add_class::<UserClient>()?;
    m.add_class::<AppClient>()?;
    m.add_class::<ApplicationLogin>()?;
    m.add_class::<ApplicationRegister>()?;
    // m.add_submodule(&internal)?;

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

impl<'py> FromPyObject<'py> for ClaimsSerialized {
    fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
        if ob.is_instance_of::<PyBytes>() {
            let claim_bytes = ob.downcast::<PyBytes>().unwrap();
            Ok(ClaimsSerialized::PyBytes(claim_bytes.clone().into()))
        } else if ob.is_instance_of::<PyDict>() {
            let claim_dict = ob.downcast::<PyDict>().unwrap();
            let mut keys: Vec<String> = Vec::with_capacity(claim_dict.len());
            let mut values: Vec<Vec<u8>> = Vec::with_capacity(claim_dict.len());

            for (i, (k, v)) in claim_dict.into_iter().enumerate() {
                let key: String = k.extract().map_err(|e| {
                    let msg = format!(
                        "Failed to convert dictionary to claims map. Key '{}' is not a string: {}",
                        k, e
                    );
                    PyValueError::new_err(msg)
                })?;

                if i != 0 {
                    let k_prev = &keys[i - 1];
                    if let Ordering::Greater = k_prev.cmp(&key) {
                        return Err(PyValueError::new_err(
                            "Claim keys are not sorted in ascending order!",
                        ));
                    }
                }

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
    PyBytes(PyBackedBytes),
}

impl ClaimsSerialized {
    fn as_bytes(&self) -> &BytePacked<Claims> {
        match &self {
            Self::PyBytes(bytes) => BytePacked::new(bytes.deref()),
            Self::Serialized(byte_owned) => byte_owned.as_packed(),
        }
    }
}

#[pyfunction]
fn create_set_claims_proof(
    py: Python<'_>,
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

    Ok(proof.encode())
}

#[pyfunction]
fn create_reset_proof(
    application: &str,
    key: &Bound<'_, ProofKey>,
    user_id: &str,
) -> PyResult<String> {
    let proof_base = ProofBaseView::new(application, &key.get().key);

    Ok(app::create_reset_proof(proof_base, user_id).encode())
}

#[pyfunction]
fn create_read_all_proof(application: &str, key: &Bound<'_, ProofKey>) -> PyResult<String> {
    let proof_base = ProofBaseView::new(application, &key.get().key);

    Ok(app::create_read_all_proof(proof_base).encode())
}

#[pyfunction]
fn create_read_some_proof(
    application: &str,
    key: &Bound<'_, ProofKey>,
    selection: Vec<String>,
) -> PyResult<String> {
    let proof_base = ProofBaseView::new(application, &key.get().key);

    Ok(app::create_read_some_proof(proof_base, selection).encode())
}

#[pyfunction]
fn create_read_range_proof(
    application: &str,
    key: &Bound<'_, ProofKey>,
    selection: Vec<String>,
) -> PyResult<String> {
    let proof_base = ProofBaseView::new(application, &key.get().key);

    Ok(app::create_read_range_proof(proof_base, selection).encode())
}
