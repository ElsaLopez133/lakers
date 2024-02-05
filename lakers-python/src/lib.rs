use lakers::BytesP256ElemLen;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod initiator;
mod responder;

/// this function is useful to test the python bindings
#[pyfunction]
fn p256_generate_key_pair() -> PyResult<(BytesP256ElemLen, BytesP256ElemLen)> {
    Ok(default_crypto().p256_generate_key_pair())
}

// this name must match `lib.name` in `Cargo.toml`
#[pymodule]
fn lakers(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(p256_generate_key_pair, m)?)?;
    m.add_class::<initiator::EdhocInitiator>()?;
    m.add_class::<responder::EdhocResponder>()?;
    // Add more functions here
    Ok(())
}
