// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Base sandbox profiles that consumers can build on top of.
//!
//! Each base is exposed as a function returning a widening [`Builder`], so a
//! worker starts from one and chains its own grants before calling
//! [`Builder::build`]:
//!
//! ```
//! use sandbox::{Network, profiles};
//!
//! let profile = profiles::minimal()
//!     .name("my_worker")
//!     .network(Network::Loopback)
//!     .build();
//! ```
//!
//! [`Builder`]: crate::Builder
//! [`Builder::build`]: crate::Builder::build

mod minimal;

pub use minimal::minimal;
