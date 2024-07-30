#[allow(nonstandard_style)]
#[allow(clippy::all)]
pub mod ffi {
    include!(concat!(env!("OUT_DIR"), "/tpa.rs"));
}
#[cfg(feature = "standalone")]
mod wrapper;
#[cfg(feature = "standalone")]
pub use wrapper::*;
