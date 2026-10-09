// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Generated protobuf / gRPC code. Module layout mirrors the protobuf
//! package hierarchy, which the generated cross-package paths rely on.

#![allow(clippy::all, missing_docs, unreachable_pub, rustdoc::all)]

macro_rules! package {
    ($name:literal) => {
        include!(concat!(env!("OUT_DIR"), "/", $name, ".rs"));
        include!(concat!(env!("OUT_DIR"), "/", $name, ".serde.rs"));
    };
}

pub mod agntcy {
    pub mod dir {
        pub mod core {
            pub mod v1 {
                package!("agntcy.dir.core.v1");
            }
        }
        pub mod events {
            pub mod v1 {
                package!("agntcy.dir.events.v1");
            }
        }
        pub mod identity {
            pub mod v1 {
                package!("agntcy.dir.identity.v1");
            }
        }
        pub mod routing {
            pub mod v1 {
                package!("agntcy.dir.routing.v1");
            }
        }
        pub mod search {
            pub mod v1 {
                package!("agntcy.dir.search.v1");
            }
        }
        pub mod sign {
            pub mod v1 {
                package!("agntcy.dir.sign.v1");
            }
        }
        pub mod store {
            pub mod v1 {
                package!("agntcy.dir.store.v1");
            }
        }
    }
}
