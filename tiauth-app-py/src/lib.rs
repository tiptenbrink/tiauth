use std::borrow::Cow;

use pyo3::types::PyBytes;
use pyo3::prelude::*;
use tiauth_core::api::app;

#[pymodule]
fn tiauth_app_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let internal = PyModule::new_bound(m.py(), "_internal")?;
    internal.add_function(wrap_pyfunction!(create_private_key_pem, &internal)?)?;
    internal.add_function(wrap_pyfunction!(public_from_private_key_pem, &internal)?)?;
    internal.add_function(wrap_pyfunction!(create_proof, &internal)?)?;

    m.add_submodule(&internal)?;

    Ok(())
}

#[pyfunction]
fn create_private_key_pem(
) -> PyResult<String> {
    Ok(app::create_private_key_pem())
}

#[pyfunction]
fn public_from_private_key_pem(
    private_key_pem: &str
) -> PyResult<String> {
    Ok(app::public_from_private_key_pem(private_key_pem))
}

#[pyfunction]
fn create_proof<'a>(
    proof_use: &[u8], application: &str, private_key_pem: &str, expires_in: Option<u64>
) -> PyResult<Cow<'a, [u8]>> {
    let proof_bytes = app::create_proof(proof_use, application, private_key_pem, expires_in);
    //let bytes = PyBytes::new_bound(py, &proof_bytes);
    Ok(Cow::from(proof_bytes))
}