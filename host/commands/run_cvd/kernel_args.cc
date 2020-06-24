/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "host/commands/run_cvd/kernel_args.h"

#include <string>
#include <vector>

#include <android-base/strings.h>
#include <android-base/logging.h>

#include <libavb/libavb.h>

#include "common/libs/fs/shared_buf.h"

#include "host/commands/run_cvd/launch.h"
#include "host/commands/run_cvd/runner_defs.h"
#include "host/libs/config/cuttlefish_config.h"
#include "host/libs/vm_manager/vm_manager.h"

template<typename T>
static void AppendVector(std::vector<T>* destination, const std::vector<T>& source) {
  destination->insert(destination->end(), source.begin(), source.end());
}

template<typename S, typename T>
static std::string concat(const S& s, const T& t) {
  std::ostringstream os;
  os << s << t;
  return os.str();
}

static size_t CalculateVbmetaSize(const cuttlefish::CuttlefishConfig& config) {
  auto vbmeta_fd = cuttlefish::SharedFD::Open(config.vbmeta_image_path(), O_RDONLY);
  if (!vbmeta_fd->IsOpen()) {
    LOG(ERROR) << "Could not open vbmeta file \""
               << config.vbmeta_image_path() << "\": "
               << vbmeta_fd->StrError();
    return 0;
  }

  auto vbmeta_system_fd =
      cuttlefish::SharedFD::Open(config.vbmeta_system_image_path(), O_RDONLY);
   if (!vbmeta_system_fd->IsOpen()) {
    LOG(ERROR) << "Could not open vbmeta file \""
               << config.vbmeta_system_image_path() << "\": "
               << vbmeta_system_fd->StrError();
    return 0;
  }

  AvbVBMetaImageHeader vbmeta_header;

  if (cuttlefish::ReadExactBinary(vbmeta_fd, &vbmeta_header) < 0) {
    LOG(ERROR) << "Could not read vbmeta file \""
               << config.vbmeta_system_image_path() << '"';
    return 0;
  }
  AvbVBMetaImageHeader vbmeta_header_swapped;
  avb_vbmeta_image_header_to_host_byte_order(&vbmeta_header,
                                             &vbmeta_header_swapped);

  if (cuttlefish::ReadExactBinary(vbmeta_system_fd, &vbmeta_header) < 0) {
    LOG(ERROR) << "Could not read vbmeta file \""
               << config.vbmeta_system_image_path() << '"';
    return 0;
  }
  AvbVBMetaImageHeader vbmeta_system_header_swapped;
  avb_vbmeta_image_header_to_host_byte_order(&vbmeta_header,
                                             &vbmeta_system_header_swapped);

  return sizeof(AvbVBMetaImageHeader) +
         vbmeta_header_swapped.authentication_data_block_size +
         vbmeta_header_swapped.auxiliary_data_block_size +
         sizeof(AvbVBMetaImageHeader) +
         vbmeta_system_header_swapped.authentication_data_block_size +
         vbmeta_system_header_swapped.auxiliary_data_block_size;
}

static std::string CalculateVbmetaDigest(const cuttlefish::CuttlefishConfig& config) {
  cuttlefish::Command avbtool_cmd(cuttlefish::DefaultHostArtifactsPath("bin/avbtool"));
  avbtool_cmd.AddParameter("calculate_vbmeta_digest");
  avbtool_cmd.AddParameter("--image");
  avbtool_cmd.AddParameter(config.vbmeta_image_path());
  avbtool_cmd.AddParameter("--hash_algorithm");
  avbtool_cmd.AddParameter("sha256");
  std::string avbtool_output;
  auto avbtool_ret = cuttlefish::RunWithManagedStdio(std::move(avbtool_cmd), nullptr,
                                              &avbtool_output, nullptr);
  if (avbtool_ret != 0) {
    LOG(ERROR) << "`avbtool \"" << config.vbmeta_image_path()
               << "\"` returned " << avbtool_ret;
  }
  return avbtool_ret == 0 ? android::base::Split(avbtool_output, "\n").at(0) : "";
}

std::vector<std::string> KernelCommandLineFromConfig(const cuttlefish::CuttlefishConfig& config) {
  std::vector<std::string> kernel_cmdline;

  AppendVector(&kernel_cmdline, config.boot_image_kernel_cmdline());
  AppendVector(&kernel_cmdline,
               vm_manager::VmManager::ConfigureGpuMode(config.vm_manager(), config.gpu_mode()));
  AppendVector(&kernel_cmdline, vm_manager::VmManager::ConfigureBootDevices(config.vm_manager()));

  kernel_cmdline.push_back(concat("androidboot.serialno=", config.serial_number()));
  kernel_cmdline.push_back(concat("androidboot.lcd_density=", config.dpi()));
  if (config.logcat_mode() == cuttlefish::kLogcatVsockMode) {
  }
  kernel_cmdline.push_back(concat(
      "androidboot.setupwizard_mode=", config.setupwizard_mode()));
  if (!config.use_bootloader()) {
    std::string slot_suffix;
    if (config.boot_slot().empty()) {
      slot_suffix = "_a";
    } else {
      slot_suffix = "_" + config.boot_slot();
    }
    kernel_cmdline.push_back(concat("androidboot.slot_suffix=", slot_suffix));
  }
  kernel_cmdline.push_back(concat("loop.max_part=", config.loop_max_part()));
  if (config.guest_enforce_security()) {
    kernel_cmdline.push_back("enforcing=1");
  } else {
    kernel_cmdline.push_back("enforcing=0");
    kernel_cmdline.push_back("androidboot.selinux=permissive");
  }
  if (config.guest_audit_security()) {
    kernel_cmdline.push_back("audit=1");
  } else {
    kernel_cmdline.push_back("audit=0");
  }

  kernel_cmdline.push_back("androidboot.verifiedbootstate=orange");
  kernel_cmdline.push_back("androidboot.vbmeta.hash_alg=sha256");
  kernel_cmdline.push_back(concat("androidboot.vbmeta.size=", CalculateVbmetaSize(config)));
  kernel_cmdline.push_back(concat("androidboot.vbmeta.digest=", CalculateVbmetaDigest(config)));

  AppendVector(&kernel_cmdline, config.extra_kernel_cmdline());

  return kernel_cmdline;
}

std::vector<std::string> KernelCommandLineFromStreamer(
    const StreamerLaunchResult& streamer_launch) {
  std::vector<std::string> kernel_args;
  if (streamer_launch.frames_server_vsock_port) {
    kernel_args.push_back(concat("androidboot.vsock_frames_port=",
                                 *streamer_launch.frames_server_vsock_port));
  }
  if (streamer_launch.touch_server_vsock_port) {
    kernel_args.push_back(concat("androidboot.vsock_touch_port=",
                                 *streamer_launch.touch_server_vsock_port));
  }
  if (streamer_launch.keyboard_server_vsock_port) {
    kernel_args.push_back(concat("androidboot.vsock_keyboard_port=",
                                 *streamer_launch.keyboard_server_vsock_port));
  }
  return kernel_args;
}

std::vector<std::string> KernelCommandLineFromTombstone(const TombstoneReceiverPorts& tombstone) {
  if (!tombstone.server_vsock_port) {
    return { "androidboot.tombstone_transmit=0" };
  }
  return {
    "androidboot.tombstone_transmit=1",
    concat("androidboot.vsock_tombstone_port=", *tombstone.server_vsock_port),
  };
}

std::vector<std::string> KernelCommandLineFromConfigServer(const ConfigServerPorts& config_server) {
  if (!config_server.server_vsock_port) {
    return {};
  }
  return {
    concat("androidboot.cuttlefish_config_server_port=", *config_server.server_vsock_port),
  };
}

std::vector<std::string> KernelCommandLineFromLogcatServer(const LogcatServerPorts& logcat_server) {
  if (!logcat_server.server_vsock_port) {
    return {};
  }
  return {
    concat("androidboot.vsock_logcat_port=", *logcat_server.server_vsock_port),
  };
}
