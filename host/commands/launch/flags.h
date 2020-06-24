#pragma once

#include "host/libs/config/cuttlefish_config.h"

cuttlefish::CuttlefishConfig* InitFilesystemAndCreateConfig(int* argc, char*** argv);
std::string GetConfigFilePath(const cuttlefish::CuttlefishConfig& config);
