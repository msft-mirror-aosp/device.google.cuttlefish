//
// Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include <optional>
#include <string>

#include "common/libs/utils/subprocess.h"
#include "host/libs/vm_manager/pci.h"

namespace cuttlefish {

class CrosvmBuilder {
 public:
  CrosvmBuilder();

  void ApplyProcessRestarter(const std::string& crosvm_binary,
                             const std::string& first_time_argument,
                             int exit_code);
  void AddControlSocket(const std::string&, const std::string&);

  void AddHvcSink();
  void AddHvcReadOnly(const std::string& output, bool console = false);
  void AddHvcReadWrite(const std::string& output, const std::string& input);

  void AddReadOnlyDisk(const std::string& path);
  void AddReadWriteDisk(const std::string& path);

  void AddSerialSink();
  void AddSerialConsoleReadOnly(const std::string& output);
  void AddSerialConsoleReadWrite(const std::string& output,
                                 const std::string& input, bool earlycon);
  // [[deprecated("do not add any more users")]]
  void AddSerial(const std::string& output, const std::string& input);

#ifdef __linux__
  void AddTap(const std::string& tap_name,
              std::optional<std::string_view> mac = std::nullopt,
              const std::optional<pci::Address>& pci = std::nullopt);
#endif

  int HvcNum();

  Command& Cmd();

 private:
  Command command_;
  int hvc_num_;
  int serial_num_;
};

}  // namespace cuttlefish
