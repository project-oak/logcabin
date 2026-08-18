//
// Copyright 2026 The LogCabin Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! LogCabin enclave app runs in a TEE on Oak Restricted kernel and serves
//! EndorserService over MicroRPC.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::boxed::Box;

use endorser_micro_rpc_service::logcabin::proto::EndorserServiceServer;
use log::debug;
use logcabin_endorser_service::EndorserService;
use oak_restricted_kernel_sdk::{
    attestation::InstanceAttester,
    channel::{start_blocking_server, FileDescriptorChannel},
    crypto::InstanceSigner,
    entrypoint,
    utils::samplestore::StaticSampleStore,
};

#[entrypoint]
fn run_server() -> ! {
    let mut invocation_stats = StaticSampleStore::<1000>::new().unwrap();

    debug!("Creating instance attester and signer.");
    let attester = InstanceAttester::create().expect("couldn't create instance attester");
    let signer = InstanceSigner::create().expect("couldn't create instance signer");

    debug!("Creating service and launching server.");
    let service = EndorserService::new(attester, signer).expect("couldn't create endorser service");
    let server = EndorserServiceServer::new(service);
    start_blocking_server(
        Box::<FileDescriptorChannel>::default(),
        server,
        &mut invocation_stats,
    )
    .expect("server encountered an unrecoverable error");
}
