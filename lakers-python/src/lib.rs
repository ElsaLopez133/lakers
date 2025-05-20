/// This file implements the python bindings for the lakers library.
/// Note that this module is not restricted by no_std.
use lakers::*;
// use lakers_ead_authz::consts::*;
use env_logger;
use lakers_crypto::{default_crypto, CryptoTrait};
use log::trace;
use pyo3::wrap_pyfunction;
use pyo3::{prelude::*, types::PyBytes};

mod ead_authz;
mod initiator;
mod responder;

/// Error raised when operations on a Python object did not happen in the sequence in which they
/// were intended.
///
/// This currently has no more detailed response because for every situation this can occur in,
/// there are different possible explainations that we can't get across easily in a single message.
/// For example, if `responder.processing_m1` is absent, that can be either because no message 1
/// was processed into it yet, or because message 2 was already generated.
#[derive(Debug)]
pub(crate) struct StateMismatch;

impl std::error::Error for StateMismatch {}
impl std::fmt::Display for StateMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Type state mismatch")
    }
}
impl From<StateMismatch> for PyErr {
    fn from(err: StateMismatch) -> PyErr {
        pyo3::exceptions::PyRuntimeError::new_err(err.to_string())
    }
}

// NOTE: throughout this implementation, we use Vec<u8> for incoming byte lists and PyBytes for outgoing byte lists.
// This is because the incoming lists of bytes are automatically converted to `Vec<u8>` by pyo3,
// but the outgoing ones must be explicitly converted to `PyBytes`.

// NOTE: using inverted parameters from rust version (credential_check_or_fetch)
// since, in Python, parameters that can be None come later
#[pyfunction(name = "credential_check_or_fetch")]
#[pyo3(signature = (id_cred_received, cred_expected=None))]
pub fn py_credential_check_or_fetch<'a>(
    py: Python<'a>,
    id_cred_received: Vec<u8>,
    cred_expected: Option<AutoCredential>,
) -> PyResult<Bound<'a, PyBytes>> {
    let valid_cred = credential_check_or_fetch(
        cred_expected.map(|c| c.to_credential()).transpose()?,
        IdCred::from_full_value(id_cred_received.as_slice())?,
    )?;

    Ok(PyBytes::new_bound(py, valid_cred.bytes.as_slice()))
}

/// this function is useful to test the python bindings
#[pyfunction]
fn p256_generate_key_pair<'a>(
    py: Python<'a>,
) -> PyResult<(Bound<'a, PyBytes>, Bound<'a, PyBytes>)> {
    let (x, g_x) = default_crypto().p256_generate_key_pair();
    Ok((
        PyBytes::new_bound(py, x.as_slice()),
        PyBytes::new_bound(py, g_x.as_slice()),
    ))
}

/// Helper for PyO3 converted functions that behave like passing an argument through a
/// `Credential` constructor; use this in an argument and then call [self.to_credential()].
/// The resulting function will accept both a bytes-ish object (and pass it through
/// [Credential::new()] or a preexisting [Credential].
#[derive(FromPyObject)]
pub enum AutoCredential {
    #[pyo3(transparent, annotation = "bytes")]
    Parse(Vec<u8>),
    #[pyo3(transparent, annotation = "Credential")]
    Existing(lakers_shared::Credential),
}

impl AutoCredential {
    pub fn to_credential(self) -> PyResult<Credential> {
        use AutoCredential::*;
        Ok(match self {
            Existing(e) => e,
            Parse(v) => Credential::parse_ccs_symmetric(v.as_slice())?,
        })
    }
}


// #[derive(FromPyObject, Clone)]
// pub enum AutoCredential {
//     #[pyo3(transparent, annotation = "bytes")]
//     Parse(Vec<u8>),
//     #[pyo3(transparent, annotation = "Credential")]
//     Existing(lakers_shared::Credential),
//     #[pyo3(transparent, annotation = "(bytes, vec)")]
//     ParseWithMethod(Vec<u8>, i32),
// }

// impl AutoCredential {
//     pub fn to_credential(self) -> PyResult<Credential> {
//         use AutoCredential::*;
//         Ok(match self {
//             Existing(e) => e,
//             Parse(v) => Credential::parse_ccs_symmetric(v.as_slice())?,
//             ParseWithMethod(v, method) => {
//                 match method {
//                     5 => Credential::parse_ccs_symmetric(v.as_slice())?,
//                     3 => Credential::parse_ccs(v.as_slice())?,
//                     _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
//                         format!("Invalid parsing method: Expected 3 or 5")
//                     )),
//                 }
//             }
//         })
//     }
// }

// this name must match `lib.name` in `Cargo.toml`
#[pymodule]
#[pyo3(name = "lakers")]
fn lakers_python(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // initialize the logger once when the module is imported
    if env_logger::try_init().is_ok() {
        trace!("lakers-python initialized from Rust side.");
    }

    m.add_function(wrap_pyfunction!(p256_generate_key_pair, m)?)?;
    m.add_function(wrap_pyfunction!(py_credential_check_or_fetch, m)?)?;
    // edhoc items
    m.add_class::<initiator::PyEdhocInitiator>()?;
    m.add_class::<responder::PyEdhocResponder>()?;
    m.add_class::<lakers::CredentialTransfer>()?;
    m.add_class::<lakers::EADItem>()?;
    m.add_class::<lakers::Credential>()?;
    // ead-authz items
    m.add_class::<ead_authz::PyAuthzDevice>()?;
    m.add_class::<ead_authz::PyAuthzAutenticator>()?;
    m.add_class::<ead_authz::PyAuthzEnrollmentServer>()?;
    m.add_class::<ead_authz::PyAuthzServerUserAcl>()?;

    let submodule = PyModule::new_bound(_py, "consts")?;
    submodule.add("EAD_AUTHZ_LABEL", lakers_ead_authz::consts::EAD_AUTHZ_LABEL)?;
    m.add_submodule(&submodule)?;
    Ok(())
}