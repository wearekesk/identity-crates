//! MRZ parser module.
//!
//! Declares the submodules for the MRZ parser and re-exports the common
//! top-level types.

pub mod country_patterns;
pub mod exceptions;
pub mod parser;
pub mod result;
pub mod sex;

mod checkdigit_calculator;
mod field_parser;
mod field_recognition_defects_fixer;
pub mod string_extensions;
mod td1_format_mrz_parser;
mod td2_format_mrz_parser;
mod td3_format_mrz_parser;

pub use checkdigit_calculator::get_check_digit;
pub use exceptions::MRZError;
pub use parser::MRZParser;
pub use result::MRZResult;
pub use sex::Sex;
