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

#include <memory>
#include <ostream>
#include <string_view>

#include "absl/container/flat_hash_map.h"
#include "absl/log/log.h"
#include "sandboxed_api/sandbox2/policybuilder.h"
#include "sandboxed_api/util/path.h"

#include "host/commands/process_sandboxer/proxy_common.h"

using sapi::file::JoinPath;

namespace cuttlefish {
namespace process_sandboxer {

std::ostream& operator<<(std::ostream& out, const HostInfo& host) {
  out << "HostInfo {\n";
  out << "\tartifacts_path: \"" << host.artifacts_path << "\"\n";
  out << "\tcuttlefish_config_path: \"" << host.cuttlefish_config_path
      << "\"\n";
  out << "\tenvironments_dir: \"" << host.environments_dir << "\"\n";
  out << "\tenvironments_uds_dir: " << host.environments_uds_dir << "\"\n";
  out << "\tinstance_uds_dir: " << host.instance_uds_dir << "\"\n";
  out << "\tlog_dir: " << host.log_dir << "\"\n";
  out << "\truntime_dir: " << host.runtime_dir << "\"\n";
  return out << "}";
}

std::unique_ptr<sandbox2::Policy> PolicyForExecutable(
    const HostInfo& host, std::string_view server_socket_outside_path,
    std::string_view executable) {
  using Builder = sandbox2::PolicyBuilder(const HostInfo&);
  absl::flat_hash_map<std::string, Builder*> builders;

  builders[JoinPath(host.artifacts_path, "bin", "kernel_log_monitor")] =
      KernelLogMonitorPolicy;
  builders[JoinPath(host.artifacts_path, "bin", "logcat_receiver")] =
      LogcatReceiverPolicy;
  builders[JoinPath(host.artifacts_path, "bin", "secure_env")] =
      SecureEnvPolicy;

  // TODO(schuffelen): Don't include test policies in the production impl
  builders[JoinPath(host.artifacts_path, "testcases", "process_sandboxer_test",
                    "x86_64", "process_sandboxer_test_hello_world")] =
      HelloWorldPolicy;

  if (auto it = builders.find(executable); it != builders.end()) {
    // TODO(schuffelen): Only share this with executables known to launch others
    return (it->second)(host)
        .AddFileAt(server_socket_outside_path, kManagerSocketPath, false)
        .BuildOrDie();
  } else {
    // TODO(schuffelen): Explicitly cover which executables need policies
    LOG(WARNING) << "No policy defined for '" << executable << "'";
    return nullptr;
  }
}

}  // namespace process_sandboxer
}  // namespace cuttlefish
