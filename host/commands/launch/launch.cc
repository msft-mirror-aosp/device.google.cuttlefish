#include "host/commands/launch/launch.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <glog/logging.h>

#include "common/libs/fs/shared_fd.h"
#include "common/libs/utils/files.h"
#include "common/libs/utils/size_utils.h"
#include "host/commands/launch/launcher_defs.h"
#include "host/commands/launch/pre_launch_initializers.h"
#include "host/libs/vm_manager/crosvm_manager.h"
#include "host/libs/vm_manager/qemu_manager.h"

using cuttlefish::LauncherExitCodes;
using cuttlefish::MonitorEntry;

namespace {

std::string GetAdbConnectorTcpArg() {
  return std::string{"127.0.0.1:"} + std::to_string(GetHostPort());
}

std::string GetAdbConnectorVsockArg(const vsoc::CuttlefishConfig& config) {
  return std::string{"vsock:"}
      + std::to_string(config.vsock_guest_cid())
      + std::string{":5555"};
}

bool AdbModeEnabled(const vsoc::CuttlefishConfig& config, vsoc::AdbMode mode) {
  return config.adb_mode().count(mode) > 0;
}

bool AdbVsockTunnelEnabled(const vsoc::CuttlefishConfig& config) {
  return config.vsock_guest_cid() > 2
      && AdbModeEnabled(config, vsoc::AdbMode::VsockTunnel);
}

bool AdbVsockHalfTunnelEnabled(const vsoc::CuttlefishConfig& config) {
  return config.vsock_guest_cid() > 2
      && AdbModeEnabled(config, vsoc::AdbMode::VsockHalfTunnel);
}

bool AdbTcpConnectorEnabled(const vsoc::CuttlefishConfig& config) {
  bool vsock_tunnel = AdbVsockTunnelEnabled(config);
  bool vsock_half_tunnel = AdbVsockHalfTunnelEnabled(config);
  return config.run_adb_connector() && (vsock_tunnel || vsock_half_tunnel);
}

bool AdbVsockConnectorEnabled(const vsoc::CuttlefishConfig& config) {
  return config.run_adb_connector()
      && AdbModeEnabled(config, vsoc::AdbMode::NativeVsock);
}

cuttlefish::OnSocketReadyCb GetOnSubprocessExitCallback(
    const vsoc::CuttlefishConfig& config) {
  if (config.restart_subprocesses()) {
    return cuttlefish::ProcessMonitor::RestartOnExitCb;
  } else {
    return cuttlefish::ProcessMonitor::DoNotMonitorCb;
  }
}
} // namespace

int GetHostPort() {
  constexpr int kFirstHostPort = 6520;
  return vsoc::GetPerInstanceDefault(kFirstHostPort);
}

bool LogcatReceiverEnabled(const vsoc::CuttlefishConfig& config) {
  return config.logcat_mode() == cuttlefish::kLogcatVsockMode;
}

void ValidateAdbModeFlag(const vsoc::CuttlefishConfig& config) {
  if (!AdbVsockTunnelEnabled(config) && !AdbVsockHalfTunnelEnabled(config)) {
    LOG(INFO) << "ADB not enabled";
  }
}

std::vector<cuttlefish::SharedFD> LaunchKernelLogMonitor(
    const vsoc::CuttlefishConfig& config,
    cuttlefish::ProcessMonitor* process_monitor,
    unsigned int number_of_event_pipes) {
  auto log_name = config.kernel_log_pipe_name();
  if (mkfifo(log_name.c_str(), 0600) != 0) {
    LOG(ERROR) << "Unable to create named pipe at " << log_name << ": "
               << strerror(errno);
    return {};
  }

  cuttlefish::SharedFD pipe;
  // Open the pipe here (from the launcher) to ensure the pipe is not deleted
  // due to the usage counters in the kernel reaching zero. If this is not done
  // and the kernel_log_monitor crashes for some reason the VMM may get SIGPIPE.
  pipe = cuttlefish::SharedFD::Open(log_name.c_str(), O_RDWR);
  cuttlefish::Command command(config.kernel_log_monitor_binary());
  command.AddParameter("-log_pipe_fd=", pipe);

  std::vector<cuttlefish::SharedFD> ret;

  if (number_of_event_pipes > 0) {
    auto param_builder = command.GetParameterBuilder();
    param_builder << "-subscriber_fds=";
    for (unsigned int i = 0; i < number_of_event_pipes; ++i) {
      cuttlefish::SharedFD event_pipe_write_end, event_pipe_read_end;
      if (!cuttlefish::SharedFD::Pipe(&event_pipe_read_end, &event_pipe_write_end)) {
        LOG(ERROR) << "Unable to create boot events pipe: " << strerror(errno);
        std::exit(LauncherExitCodes::kPipeIOError);
      }
      if (i > 0) {
        param_builder << ",";
      }
      param_builder << event_pipe_write_end;
      ret.push_back(event_pipe_read_end);
    }
    param_builder.Build();
  }

  process_monitor->StartSubprocess(std::move(command),
                                   GetOnSubprocessExitCallback(config));

  return ret;
}

void LaunchLogcatReceiverIfEnabled(const vsoc::CuttlefishConfig& config,
                                   cuttlefish::ProcessMonitor* process_monitor) {
  if (!LogcatReceiverEnabled(config)) {
    return;
  }
  auto port = config.logcat_vsock_port();
  auto socket = cuttlefish::SharedFD::VsockServer(port, SOCK_STREAM);
  if (!socket->IsOpen()) {
    LOG(ERROR) << "Unable to create logcat server socket: "
               << socket->StrError();
    std::exit(LauncherExitCodes::kLogcatServerError);
  }
  cuttlefish::Command cmd(config.logcat_receiver_binary());
  cmd.AddParameter("-server_fd=", socket);
  process_monitor->StartSubprocess(std::move(cmd),
                                   GetOnSubprocessExitCallback(config));
}

void LaunchConfigServer(const vsoc::CuttlefishConfig& config,
                        cuttlefish::ProcessMonitor* process_monitor) {
  auto port = config.config_server_port();
  auto socket = cuttlefish::SharedFD::VsockServer(port, SOCK_STREAM);
  if (!socket->IsOpen()) {
    LOG(ERROR) << "Unable to create configuration server socket: "
               << socket->StrError();
    std::exit(LauncherExitCodes::kConfigServerError);
  }
  cuttlefish::Command cmd(config.config_server_binary());
  cmd.AddParameter("-server_fd=", socket);
  process_monitor->StartSubprocess(std::move(cmd),
                                   GetOnSubprocessExitCallback(config));
}

cuttlefish::SharedFD CreateUnixVncInputServer(const std::string& path) {
  auto server = cuttlefish::SharedFD::SocketLocalServer(path.c_str(), false, SOCK_STREAM, 0666);
  if (!server->IsOpen()) {
    LOG(ERROR) << "Unable to create unix input server: "
               << server->StrError();
    return cuttlefish::SharedFD();
  }
  return server;
}

cuttlefish::SharedFD CreateVsockVncInputServer(int port) {
  auto server = cuttlefish::SharedFD::VsockServer(port, SOCK_STREAM);
  if (!server->IsOpen()) {
    LOG(ERROR) << "Unable to create vsock input server: "
               << server->StrError();
    return cuttlefish::SharedFD();
  }
  return server;
}

bool LaunchVNCServerIfEnabled(const vsoc::CuttlefishConfig& config,
                              cuttlefish::ProcessMonitor* process_monitor,
                              std::function<bool(MonitorEntry*)> callback) {
  if (config.enable_vnc_server()) {
    // Launch the vnc server, don't wait for it to complete
    auto port_options = "-port=" + std::to_string(config.vnc_server_port());
    cuttlefish::Command vnc_server(config.vnc_server_binary());
    vnc_server.AddParameter(port_options);
    if (config.vm_manager() == vm_manager::QemuManager::name()) {
      vnc_server.AddParameter("-write_virtio_input");
    }
    // The vnc touch_server needs to serve
    // on sockets and send input events to whoever connects to it (the VMM).
    auto touch_server =
        config.vm_manager() == vm_manager::CrosvmManager::name()
            ? CreateUnixVncInputServer(config.touch_socket_path())
            : CreateVsockVncInputServer(config.touch_socket_port());
    if (!touch_server->IsOpen()) {
      return false;
    }
    vnc_server.AddParameter("-touch_fd=", touch_server);

    auto keyboard_server =
        config.vm_manager() == vm_manager::CrosvmManager::name()
            ? CreateUnixVncInputServer(config.keyboard_socket_path())
            : CreateVsockVncInputServer(config.keyboard_socket_port());
    if (!keyboard_server->IsOpen()) {
      return false;
    }
    vnc_server.AddParameter("-keyboard_fd=", keyboard_server);
    // TODO(b/128852363): This should be handled through the wayland mock
    //  instead.
    // Additionally it receives the frame updates from a virtual socket
    // instead
    auto frames_server =
        cuttlefish::SharedFD::VsockServer(config.frames_vsock_port(), SOCK_STREAM);
    if (!frames_server->IsOpen()) {
      return false;
    }
    vnc_server.AddParameter("-frame_server_fd=", frames_server);
    process_monitor->StartSubprocess(std::move(vnc_server), callback);
    return true;
  }
  return false;
}

void LaunchAdbConnectorIfEnabled(cuttlefish::ProcessMonitor* process_monitor,
                                 const vsoc::CuttlefishConfig& config,
                                 cuttlefish::SharedFD adbd_events_pipe) {
  cuttlefish::Command adb_connector(config.adb_connector_binary());
  adb_connector.AddParameter("-adbd_events_fd=", adbd_events_pipe);
  std::set<std::string> addresses;

  if (AdbTcpConnectorEnabled(config)) {
    addresses.insert(GetAdbConnectorTcpArg());
  }
  if (AdbVsockConnectorEnabled(config)) {
    addresses.insert(GetAdbConnectorVsockArg(config));
  }

  if (addresses.size() > 0) {
    std::string address_arg = "--addresses=";
    for (auto& arg : addresses) {
      address_arg += arg + ",";
    }
    address_arg.pop_back();
    adb_connector.AddParameter(address_arg);
    process_monitor->StartSubprocess(std::move(adb_connector),
                                     GetOnSubprocessExitCallback(config));
  }
}

void LaunchSocketVsockProxyIfEnabled(cuttlefish::ProcessMonitor* process_monitor,
                                 const vsoc::CuttlefishConfig& config) {
  if (AdbVsockTunnelEnabled(config)) {
    cuttlefish::Command adb_tunnel(config.socket_vsock_proxy_binary());
    adb_tunnel.AddParameter("--vsock_port=6520");
    adb_tunnel.AddParameter(
        std::string{"--tcp_port="} + std::to_string(GetHostPort()));
    adb_tunnel.AddParameter(std::string{"--vsock_guest_cid="} +
                            std::to_string(config.vsock_guest_cid()));
    process_monitor->StartSubprocess(std::move(adb_tunnel),
                                     GetOnSubprocessExitCallback(config));
  }
  if (AdbVsockHalfTunnelEnabled(config)) {
    cuttlefish::Command adb_tunnel(config.socket_vsock_proxy_binary());
    adb_tunnel.AddParameter("--vsock_port=5555");
    adb_tunnel.AddParameter(
        std::string{"--tcp_port="} + std::to_string(GetHostPort()));
    adb_tunnel.AddParameter(std::string{"--vsock_guest_cid="} +
                            std::to_string(config.vsock_guest_cid()));
    process_monitor->StartSubprocess(std::move(adb_tunnel),
                                     GetOnSubprocessExitCallback(config));
  }
}
