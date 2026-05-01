// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This crate implements the KeyMint HAL service in Rust, communicating with a Rust
//! trusted application (TA) running on the Cuttlefish host.

use kmr_hal::{register_binder_services, HalServiceError, ALL_HALS};
use log::{error, info};
use std::fs;
use std::panic;
use std::sync::{Arc, Mutex};

/// Device file used to communicate with the KeyMint TA.
static DEVICE_FILE_NAME: &str = "/dev/hvc11";

/// Name of KeyMint binder device instance.
static SERVICE_INSTANCE: &str = "default";

/// Read-write file used for communication with host TA.
#[derive(Debug)]
struct FileChannel(std::fs::File);

impl kmr_hal::SerializedChannel for FileChannel {
    const MAX_SIZE: usize = kmr_wire::DEFAULT_MAX_SIZE;

    fn execute(&mut self, serialized_req: &[u8]) -> binder::Result<Vec<u8>> {
        kmr_hal::write_msg(&mut self.0, serialized_req)?;
        kmr_hal::read_msg(&mut self.0)
    }
}

fn make_raw(file: fs::File) -> std::io::Result<fs::File> {
    use nix::sys::termios::*;
    let mut attrs = tcgetattr(&file)?;
    cfmakeraw(&mut attrs);
    tcsetattr(&file, SetArg::TCSANOW, &attrs)?;
    Ok(file)
}

fn main() {
    if let Err(HalServiceError(e)) = inner_main() {
        panic!("HAL service failed: {e:?}");
    }
}

fn inner_main() -> Result<(), HalServiceError> {
    // Initialize android logging.
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keymint-hal")
            .with_max_level(log::LevelFilter::Info)
            .with_log_buffer(android_logger::LogId::System),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{panic_info}");
    }));

    info!("KeyMint HAL service is starting.");

    info!("Starting thread pool now.");
    binder::ProcessState::start_thread_pool();

    // Create a connection to the TA.
    let fc = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEVICE_FILE_NAME)
        .and_then(make_raw)
        .map_err(|e| {
            HalServiceError(format!("Failed to open the device file '{DEVICE_FILE_NAME}': {e:?}"))
        })?;

    let channel = Arc::new(Mutex::new(FileChannel(fc)));

    register_binder_services(&channel, ALL_HALS, SERVICE_INSTANCE)?;

    // Let the TA know information about the userspace environment.
    kmr_hal_nonsecure::send_boot_info_and_attestation_id_info(&channel)?;

    info!("Joining thread pool now.");
    binder::ProcessState::join_thread_pool();
    info!("KeyMint HAL service is terminating.");
    Ok(())
}
