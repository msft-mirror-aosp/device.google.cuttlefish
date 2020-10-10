/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "host/libs/vm_manager/crosvm_manager.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <string>
#include <vector>

#include <android-base/strings.h>
#include <glog/logging.h>
#include <vulkan/vulkan.h>

#include "common/libs/utils/environment.h"
#include "common/libs/utils/files.h"
#include "common/libs/utils/network.h"
#include "common/libs/utils/subprocess.h"
#include "host/libs/config/cuttlefish_config.h"
#include "host/libs/vm_manager/qemu_manager.h"

namespace cuttlefish {
namespace vm_manager {

namespace {

std::string GetControlSocketPath(const cuttlefish::CuttlefishConfig* config) {
  return config->ForDefaultInstance()
      .PerInstanceInternalPath("crosvm_control.sock");
}

void AddTapFdParameter(cuttlefish::Command* crosvm_cmd, const std::string& tap_name) {
  auto tap_fd = cuttlefish::OpenTapInterface(tap_name);
  if (tap_fd->IsOpen()) {
    crosvm_cmd->AddParameter("--tap-fd");
    crosvm_cmd->AddParameter(tap_fd);
  } else {
    LOG(ERROR) << "Unable to connect to " << tap_name << ": "
               << tap_fd->StrError();
  }
}

bool Stop() {
  auto config = cuttlefish::CuttlefishConfig::Get();
  cuttlefish::Command command(config->crosvm_binary());
  command.AddParameter("stop");
  command.AddParameter(GetControlSocketPath(config));

  auto process = command.Start();

  return process.Wait() == 0;
}

}  // namespace

const std::string CrosvmManager::name() { return "crosvm"; }

std::vector<std::string> CrosvmManager::ConfigureGpu(const std::string& gpu_mode) {
  // Override the default HAL search paths in all cases. We do this because
  // the HAL search path allows for fallbacks, and fallbacks in conjunction
  // with properities lead to non-deterministic behavior while loading the
  // HALs.
  if (gpu_mode == cuttlefish::kGpuModeGuestSwiftshader) {
    return {
        "androidboot.cpuvulkan.version=" + std::to_string(VK_API_VERSION_1_1),
        "androidboot.hardware.gralloc=minigbm",
        "androidboot.hardware.hwcomposer=cutf",
        "androidboot.hardware.egl=angle",
        "androidboot.hardware.vulkan=pastel",
    };
  }

  // Try to load the Nvidia modeset kernel module. Running Crosvm with Nvidia's EGL library on a
  // fresh machine after a boot will fail because the Nvidia EGL library will fork to run the
  // nvidia-modprobe command and the main Crosvm process will abort after receiving the exit signal
  // of the forked child which is interpreted as a failure.
  cuttlefish::Command modprobe_cmd("/usr/bin/nvidia-modprobe");
  modprobe_cmd.AddParameter("--modeset");
  modprobe_cmd.Start().Wait();

  if (gpu_mode == cuttlefish::kGpuModeDrmVirgl) {
    return {
      "androidboot.cpuvulkan.version=0",
      "androidboot.hardware.gralloc=minigbm",
      "androidboot.hardware.hwcomposer=drm_minigbm",
      "androidboot.hardware.egl=mesa",
    };
  }
  if (gpu_mode == cuttlefish::kGpuModeGfxStream) {
    return {
        "androidboot.cpuvulkan.version=0",
        "androidboot.hardware.gralloc=minigbm",
        "androidboot.hardware.hwcomposer=drm_minigbm",
        "androidboot.hardware.egl=emulation",
        "androidboot.hardware.vulkan=ranchu",
        "androidboot.hardware.gltransport=virtio-gpu-pipe",
    };
  }
  return {};
}

std::vector<std::string> CrosvmManager::ConfigureBootDevices() {
  // TODO There is no way to control this assignment with crosvm (yet)
  if (cuttlefish::HostArch() == "x86_64") {
    // PCI domain 0, bus 0, device 6, function 0
    return { "androidboot.boot_devices=pci0000:00/0000:00:06.0" };
  } else {
    return { "androidboot.boot_devices=10000.pci" };
  }
}

CrosvmManager::CrosvmManager(const cuttlefish::CuttlefishConfig* config)
    : VmManager(config) {}

std::vector<cuttlefish::Command> CrosvmManager::StartCommands() {
  auto instance = config_->ForDefaultInstance();
  cuttlefish::Command crosvm_cmd(config_->crosvm_binary(), [](cuttlefish::Subprocess* proc) {
    auto stopped = Stop();
    if (stopped) {
      return true;
    }
    LOG(WARNING) << "Failed to stop VMM nicely, attempting to KILL";
    return KillSubprocess(proc);
  });
  crosvm_cmd.AddParameter("run");

  auto gpu_mode = config_->gpu_mode();

  crosvm_cmd.AddParameter("--gpu");
  if (gpu_mode == cuttlefish::kGpuModeGuestSwiftshader) {
    crosvm_cmd.AddParameter("2D,width=", config_->x_res(), ",",
                            "height=", config_->y_res());
  } else if (gpu_mode == cuttlefish::kGpuModeDrmVirgl ||
             gpu_mode == cuttlefish::kGpuModeGfxStream) {
    crosvm_cmd.AddParameter(gpu_mode == cuttlefish::kGpuModeGfxStream ?
                                "gfxstream," : "",
                            "width=", config_->x_res(), ",",
                            "height=", config_->y_res(), ",",
                            "egl=true,surfaceless=true,glx=false,gles=true");
  }
  crosvm_cmd.AddParameter("--wayland-sock");
  crosvm_cmd.AddParameter(instance.frames_socket_path());
  if (!config_->use_bootloader() && !config_->final_ramdisk_path().empty()) {
    crosvm_cmd.AddParameter("--initrd=", config_->final_ramdisk_path());
  }
  crosvm_cmd.AddParameter("--mem");
  crosvm_cmd.AddParameter(config_->memory_mb());
  crosvm_cmd.AddParameter("--cpus");
  crosvm_cmd.AddParameter(config_->cpus());
  crosvm_cmd.AddParameter("--params");
  crosvm_cmd.AddParameter(kernel_cmdline_);
  for (const auto& disk : instance.virtual_disk_paths()) {
    crosvm_cmd.AddParameter("--rwdisk");
    crosvm_cmd.AddParameter(disk);
  }
  crosvm_cmd.AddParameter("--socket");
  crosvm_cmd.AddParameter(GetControlSocketPath(config_));

  if (frontend_enabled_) {
    crosvm_cmd.AddParameter("--single-touch");
    crosvm_cmd.AddParameter(instance.touch_socket_path(),
                            ":", config_->x_res(), ":", config_->y_res());
    crosvm_cmd.AddParameter("--keyboard");
    crosvm_cmd.AddParameter(instance.keyboard_socket_path());
  }

  AddTapFdParameter(&crosvm_cmd, instance.wifi_tap_name());
  AddTapFdParameter(&crosvm_cmd, instance.mobile_tap_name());

  crosvm_cmd.AddParameter("--rw-pmem-device");
  crosvm_cmd.AddParameter(instance.access_kregistry_path());
  crosvm_cmd.AddParameter("--pstore");
  crosvm_cmd.AddParameter("path=", instance.pstore_path(), ",size=",
                          cuttlefish::FileSize(instance.pstore_path()));

  // TODO remove this (use crosvm's seccomp files)
  crosvm_cmd.AddParameter("--disable-sandbox");

  if (instance.vsock_guest_cid() >= 2) {
    crosvm_cmd.AddParameter("--cid");
    crosvm_cmd.AddParameter(instance.vsock_guest_cid());
  }

  // Use an 8250 UART (ISA or platform device) for earlycon, as the
  // virtio-console driver may not be available for early messages
  // In kgdb mode, earlycon is an interactive console, and so early
  // dmesg will go there instead of the kernel.log
  if (!(config_->console() && (config_->use_bootloader() || config_->kgdb()))) {
    crosvm_cmd.AddParameter("--serial");
    crosvm_cmd.AddParameter("hardware=serial,num=1,type=file,path=",
                            instance.kernel_log_pipe_name(), ",earlycon=true");
  }

  // Use a virtio-console instance for the main kernel console. All
  // messages will switch from earlycon to virtio-console after the driver
  // is loaded, and crosvm will append to the kernel log automatically
  crosvm_cmd.AddParameter("--serial");
  crosvm_cmd.AddParameter("hardware=virtio-console,num=1,type=file,path=",
                          instance.kernel_log_pipe_name(), ",console=true");

  if (config_->console()) {
    // stdin is the only currently supported way to write data to a serial port in
    // crosvm. A file (named pipe) is used here instead of stdout to ensure only
    // the serial port output is received by the console forwarder as crosvm may
    // print other messages to stdout.
    if (config_->kgdb() || config_->use_bootloader()) {
      crosvm_cmd.AddParameter("--serial");
      crosvm_cmd.AddParameter("hardware=serial,num=1,type=file,path=",
                              instance.console_out_pipe_name(), ",input=",
                              instance.console_in_pipe_name(), ",earlycon=true");
      // In kgdb mode, we have the interactive console on ttyS0 (both Android's
      // console and kdb), so we can disable the virtio-console port usually
      // allocated to Android's serial console, and redirect it to a sink. This
      // ensures that that the PCI device assignments (and thus sepolicy) don't
      // have to change
      crosvm_cmd.AddParameter("--serial");
      crosvm_cmd.AddParameter("hardware=virtio-console,num=2,type=sink");
    } else {
      crosvm_cmd.AddParameter("--serial");
      crosvm_cmd.AddParameter("hardware=virtio-console,num=2,type=file,path=",
                              instance.console_out_pipe_name(), ",input=",
                              instance.console_in_pipe_name());
    }
  } else {
    // as above, create a fake virtio-console 'sink' port when the serial
    // console is disabled, so the PCI device ID assignments don't move
    // around
    crosvm_cmd.AddParameter("--serial");
    crosvm_cmd.AddParameter("hardware=virtio-console,num=2,type=sink");
  }

  cuttlefish::SharedFD log_out_rd, log_out_wr;
  if (!cuttlefish::SharedFD::Pipe(&log_out_rd, &log_out_wr)) {
    LOG(ERROR) << "Failed to create log pipe for crosvm's stdout/stderr: "
               << log_out_rd->StrError();
    return {};
  }
  crosvm_cmd.RedirectStdIO(cuttlefish::Subprocess::StdIOChannel::kStdOut,
                           log_out_wr);
  crosvm_cmd.RedirectStdIO(cuttlefish::Subprocess::StdIOChannel::kStdErr,
                           log_out_wr);

  cuttlefish::Command log_tee_cmd(
      cuttlefish::DefaultHostArtifactsPath("bin/log_tee"));
  log_tee_cmd.AddParameter("--process_name=crosvm");
  log_tee_cmd.AddParameter("--log_fd_in=", log_out_rd);

  // Serial port for logcat, redirected to a pipe
  crosvm_cmd.AddParameter("--serial");
  crosvm_cmd.AddParameter("hardware=virtio-console,num=3,type=file,path=",
                          instance.logcat_pipe_name());

  // This needs to be the last parameter
  if (config_->use_bootloader()) {
    crosvm_cmd.AddParameter("--bios");
    crosvm_cmd.AddParameter(config_->bootloader());
  } else {
    crosvm_cmd.AddParameter(config_->GetKernelImageToUse());
  }

  std::vector<cuttlefish::Command> ret;
  ret.push_back(std::move(crosvm_cmd));
  ret.push_back(std::move(log_tee_cmd));
  return ret;
}

} // namespace vm_manager
} // namespace cuttlefish

