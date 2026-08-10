/*
 * Copyright (C) 2026 The Android Open Source Project
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

#define LOG_TAG "android.hardware.media.c2-service-cuttlefish"

#include <csignal>
#include <cstring>
#include <memory>

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <codec2/aidl/ComponentStore.h>
#include <minijail.h>

#include "CuttlefishComponentStore.h"

static constexpr char kBaseSeccompPolicyPath[] =
    "/vendor/etc/seccomp_policy/"
    "android.hardware.media.c2-cuttlefish-seccomp.policy";

int main(int /* argc */, char** /* argv */) {
  LOG(DEBUG) << "android.hardware.media.c2-service-cuttlefish starting...";
  signal(SIGPIPE, SIG_IGN);
  android::SetUpMinijail(kBaseSeccompPolicyPath, "");

  ABinderProcess_setThreadPoolMaxThreadCount(8);
  ABinderProcess_startThreadPool();

  using namespace ::aidl::android::hardware::media::c2;
  std::shared_ptr<C2ComponentStore> nativeStore =
      std::make_shared<android::CuttlefishComponentStore>();
  std::shared_ptr<IComponentStore> store =
      ::ndk::SharedRefBase::make<utils::ComponentStore>(nativeStore);

  const std::string serviceName =
      std::string(IComponentStore::descriptor) + "/default";
  binder_exception_t ex =
      AServiceManager_addService(store->asBinder().get(), serviceName.c_str());
  if (ex != EX_NONE) {
    LOG(ERROR) << "Cannot register Codec2 service with instance name \""
               << serviceName << "\".";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "Codec2 IComponentStore service registered as \"" << serviceName << "\"";
  ABinderProcess_joinThreadPool();
  return EXIT_FAILURE;
}
