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

#include <sandboxed_api/sandbox2/policybuilder.h>
#include <sandboxed_api/util/path.h>

namespace cuttlefish::process_sandboxer {

using sapi::file::JoinPath;

sandbox2::PolicyBuilder WmediumdGenConfigPolicy(const HostInfo& host) {
  return BaselinePolicy(host, host.HostToolExe("wmediumd_gen_config"))
      .AddDirectory(JoinPath(host.environments_dir, "env-1"),
                    /* is_ro= */ false);
}

}  // namespace cuttlefish::process_sandboxer
