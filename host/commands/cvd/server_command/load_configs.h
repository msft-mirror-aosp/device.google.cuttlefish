/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <memory>

#include "host/commands/cvd/command_sequence.h"
#include "host/commands/cvd/server_command/server_handler.h"

namespace cuttlefish {

/*
cvd load component is responsible of loading, translation and creation of
cuttlefish instances based on input json configuration file
*/
std::unique_ptr<CvdServerHandler> NewLoadConfigsCommand(
    CommandSequenceExecutor& executor);

}  // namespace cuttlefish
