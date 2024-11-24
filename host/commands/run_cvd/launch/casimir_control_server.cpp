/*
 * Copyright 2023 The Android Open Source Project
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

#include "host/commands/run_cvd/launch/launch.h"

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <fruit/fruit.h>

#include "common/libs/utils/files.h"
#include "common/libs/utils/result.h"
#include "host/commands/run_cvd/launch/grpc_socket_creator.h"
#include "host/libs/config/command_source.h"
#include "host/libs/config/known_paths.h"

namespace cuttlefish {

Result<std::optional<MonitorCommand>> CasimirControlServer(
    const CuttlefishConfig& config,
    const CuttlefishConfig::EnvironmentSpecific& environment,
    const CuttlefishConfig::InstanceSpecific& instance,
    GrpcSocketCreator& grpc_socket) {
  if (!config.enable_host_nfc()) {
    return {};
  }
  if (!instance.start_casimir()) {
    return {};
  }

  Command casimir_control_server_cmd(CasimirControlServerBinary());
  casimir_control_server_cmd.AddParameter(
      "-grpc_uds_path=", grpc_socket.CreateGrpcSocket("CasimirControlServer"));
  casimir_control_server_cmd.AddParameter("-casimir_rf_path=",
                                          environment.casimir_rf_socket_path());
  return casimir_control_server_cmd;
}

}  // namespace cuttlefish
