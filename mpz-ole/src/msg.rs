//! Message types for different OLE protocols.

use enum_try_as_inner::EnumTryAsInner;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, EnumTryAsInner, Serialize, Deserialize)]
#[derive_err(Debug)]
#[allow(missing_docs)]
/// A message type for OLEe protocols.
pub enum OLEeMessage {}

#[derive(Debug, Clone, EnumTryAsInner, Serialize, Deserialize)]
#[derive_err(Debug)]
#[allow(missing_docs)]
/// A message type for ROLEe protocols.
pub enum ROLEeMessage {}
