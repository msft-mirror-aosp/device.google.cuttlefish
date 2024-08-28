/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include "host/commands/process_sandboxer/policies.h"

#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
#include <sandboxed_api/sandbox2/policybuilder.h>
#include <sandboxed_api/sandbox2/trace_all_syscalls.h>
#include <sandboxed_api/util/path.h>

namespace cuttlefish::process_sandboxer {

using sapi::file::JoinPath;

sandbox2::PolicyBuilder WebRtcPolicy(const HostInfo& host) {
  // TODO: b/318609110 - Add system call policy. This only applies namespaces.
  return BaselinePolicy(host, host.HostToolExe("webRTC"))
      .AddDirectory(host.log_dir, /* is_ro= */ false)
      .AddDirectory(host.host_artifacts_path + "/usr/share/webrtc/assets")
      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
      .AddDirectory(JoinPath(host.runtime_dir, "recording"), /* is_ro= */ false)
      .AddFile(host.cuttlefish_config_path)
      .AddFile("/dev/urandom")
      .AddFile("/run/cuttlefish/operator")
      .Allow(sandbox2::UnrestrictedNetworking())
      .DefaultAction(sandbox2::TraceAllSyscalls());
}

}  // namespace cuttlefish::process_sandboxer
