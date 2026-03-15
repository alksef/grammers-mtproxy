// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! MTProxy network support.
//!
//! This module provides MTProxy-related functionality for the network layer.

// MTProxy connections are handled through the standard TcpStream
// via the ServerAddr::MtProxy variant in tcp.rs
