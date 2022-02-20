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

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <fruit/fruit.h>

#include "cvd_server.pb.h"

#include "common/libs/fs/shared_fd.h"
#include "common/libs/utils/result.h"
#include "common/libs/utils/unix_sockets.h"

namespace cuttlefish {

constexpr char kStopBin[] = "cvd_internal_stop";

struct RequestWithStdio {
  cvd::Request request;
  SharedFD in, out, err;
  std::optional<SharedFD> extra;
};

class CvdServerHandler {
 public:
  virtual ~CvdServerHandler() = default;

  virtual Result<bool> CanHandle(const RequestWithStdio&) const = 0;
  virtual Result<cvd::Response> Handle(const RequestWithStdio&) = 0;
};

class CvdServer {
 public:
  using AssemblyDir = std::string;
  struct AssemblyInfo {
    std::string host_binaries_dir;
  };

  INJECT(CvdServer()) = default;

  Result<void> AddHandler(CvdServerHandler* handler);

  std::map<AssemblyDir, AssemblyInfo>& Assemblies();

  void Stop();

  void ServerLoop(const SharedFD& server);

  cvd::Status CvdClear(const SharedFD& out, const SharedFD& err);

 private:
  std::map<AssemblyDir, AssemblyInfo> assemblies_;
  std::vector<CvdServerHandler*> handlers_;
  bool running_ = true;

  Result<cvd::Response> HandleRequest(const RequestWithStdio& request);

  Result<UnixMessageSocket> GetClient(const SharedFD& client) const;

  Result<RequestWithStdio> GetRequest(const SharedFD& client) const;

  Result<void> SendResponse(const SharedFD& client,
                            const cvd::Response& response) const;
};

fruit::Component<> cvdCommandComponent();
fruit::Component<> cvdShutdownComponent();
fruit::Component<> cvdVersionComponent();

std::optional<std::string> GetCuttlefishConfigPath(
    const std::string& assembly_dir);

struct CommandInvocation {
  std::string command;
  std::vector<std::string> arguments;
};

CommandInvocation ParseInvocation(const cvd::Request& request);

}  // namespace cuttlefish
