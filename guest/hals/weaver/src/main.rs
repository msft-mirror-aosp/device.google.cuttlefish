//
// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Weaver HAL service for Cuttlefish.

use android_hardware_weaver::aidl::android::hardware::weaver::IWeaver::IWeaver;
use hal_hal::channel::{read_msg, write_msg, SerializedChannel};
use log::{error, info};
use std::fs;
use std::panic;
use std::sync::{Arc, Mutex};

/// Device file used to communicate with the Weaver TA.
static DEVICE_FILE_NAME: &str = "/dev/hvc13";

/// Read-write file used for communication with host TA.
#[derive(Debug)]
struct FileChannel(std::fs::File);

impl SerializedChannel for FileChannel {
    const MAX_SIZE: usize = 4096;

    fn execute(&mut self, serialized_req: &[u8]) -> binder::Result<Vec<u8>> {
        write_msg(&mut self.0, serialized_req)?;
        read_msg(&mut self.0)
    }
}

#[derive(Debug)]
struct HalServiceError(String);

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
            .with_tag("weaver-hal")
            .with_max_level(log::LevelFilter::Info)
            .with_log_buffer(android_logger::LogId::System),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{panic_info}");
    }));

    info!("Weaver HAL service is starting.");

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

    let service = weaver_hal::WeaverService::new_as_binder(channel);

    let service_name = format!(
        "{}/default",
        <weaver_hal::WeaverService<FileChannel> as IWeaver>::get_descriptor()
    );
    binder::add_service(&service_name, service.as_binder())
        .map_err(|e| HalServiceError(format!("failed to register Weaver service: {e:?}")))?;

    info!("Joining thread pool now.");
    binder::ProcessState::join_thread_pool();
    info!("Weaver HAL service is terminating.");
    Ok(())
}
