#pragma once

#include <functional>

#include "common/libs/utils/subprocess.h"
#include "host/commands/launch/process_monitor.h"
#include "host/libs/config/cuttlefish_config.h"

int GetHostPort();
bool AdbUsbEnabled(const cuttlefish::CuttlefishConfig& config);
void ValidateAdbModeFlag(const cuttlefish::CuttlefishConfig& config);

std::vector <cuttlefish::SharedFD> LaunchKernelLogMonitor(
    const cuttlefish::CuttlefishConfig& config,
    cuttlefish::ProcessMonitor* process_monitor,
    unsigned int number_of_event_pipes);
void LaunchLogcatReceiver(const cuttlefish::CuttlefishConfig& config,
                          cuttlefish::ProcessMonitor* process_monitor);
void LaunchConfigServer(const cuttlefish::CuttlefishConfig& config,
                        cuttlefish::ProcessMonitor* process_monitor);
bool LaunchVNCServerIfEnabled(const cuttlefish::CuttlefishConfig& config,
                              cuttlefish::ProcessMonitor* process_monitor,
                              std::function<bool(cuttlefish::MonitorEntry*)> callback);
void LaunchAdbConnectorIfEnabled(cuttlefish::ProcessMonitor* process_monitor,
                                 const cuttlefish::CuttlefishConfig& config,
                                 cuttlefish::SharedFD adbd_events_pipe);
void LaunchSocketVsockProxyIfEnabled(cuttlefish::ProcessMonitor* process_monitor,
                                 const cuttlefish::CuttlefishConfig& config);
