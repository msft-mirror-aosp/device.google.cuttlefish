/*
 * Copyright (C) 2021 The Android Open Source Project
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

#pragma once
#include "common/libs/utils/vsock_connection.h"

#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

namespace cuttlefish {
namespace webrtc_streaming {

class LightsObserver {
 public:
  LightsObserver(unsigned int port, unsigned int cid);
  ~LightsObserver();

  LightsObserver(const LightsObserver& other) = delete;
  LightsObserver& operator=(const LightsObserver& other) = delete;

  bool Start();

 private:
  void Stop();
  void ReadServerMessages();
  // TODO(b/295543722): Move to a virtio_console transport instead.
  VsockClientConnection cvd_connection_;
  unsigned int cid_;
  unsigned int port_;
  std::thread connection_thread_;
  std::atomic<bool> is_running_;
  std::atomic<bool> session_active_;
};

}  // namespace webrtc_streaming
}  // namespace cuttlefish
