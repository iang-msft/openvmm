// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone CLI for exercising the [`sandbox`] crate.
//!
//! Use this launcher to invoke sandboxing primitives from the command line
//! outside of openvmm/openhcl, e.g. for iterating on new sandbox profiles.

#![forbid(unsafe_code)]

use sandbox as _;

fn main() -> anyhow::Result<()> {
    // TODO: exercise sandbox APIs here.
    Ok(())
}
