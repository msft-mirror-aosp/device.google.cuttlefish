/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "android.hardware.gatekeeper-service.remote"

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <cutils/properties.h>
#include <gflags/gflags.h>

#include "common/libs/fs/shared_fd.h"
#include "common/libs/security/gatekeeper_channel.h"
#include "guest/hals/gatekeeper/remote/remote_gatekeeper.h"
#include "remote_gatekeeper.h"

using aidl::android::hardware::gatekeeper::RemoteGateKeeperDevice;

const char device[] = "/dev/hvc4";

int main(int argc, char** argv) {
    ::android::base::InitLogging(argv, ::android::base::KernelLogger);
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    ABinderProcess_setThreadPoolMaxThreadCount(0);

    auto fd = cuttlefish::SharedFD::Open(device, O_RDWR);
    if (!fd->IsOpen()) {
        LOG(FATAL) << "Could not connect to gatekeeper: " << fd->StrError();
    }

    if (fd->SetTerminalRaw() < 0) {
        LOG(FATAL) << "Could not make " << device << " a raw terminal: " << fd->StrError();
    }

    cuttlefish::GatekeeperChannel gatekeeperChannel(fd, fd);

    std::shared_ptr<RemoteGateKeeperDevice> gatekeeper =
        ndk::SharedRefBase::make<RemoteGateKeeperDevice>(&gatekeeperChannel);

    const std::string instance = std::string() + RemoteGateKeeperDevice::descriptor + "/default";
    binder_status_t status =
        AServiceManager_addService(gatekeeper->asBinder().get(), instance.c_str());
    CHECK_EQ(status, STATUS_OK);

    ABinderProcess_joinThreadPool();
    return -1;  // Should never get here.
}
