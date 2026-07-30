/*
 * Copyright (C) 2026 The Android Open Source Project
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

#define LOG_TAG "VirtioMediaV4l2Utils"
// #define LOG_NDEBUG 0

#include "V4l2Utils.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <log/log.h>
#include <string.h>
#include <sys/ioctl.h>
#include <regex>

#include <android-base/parseint.h>
#include <android-base/result.h>

using ::android::base::borrowed_fd;
using ::android::base::ErrnoError;
using ::android::base::Result;

namespace cuttlefish {
namespace virtio_media {
namespace {

Result<std::optional<uint32_t>> CtrlId(borrowed_fd fd,
                                       const std::string& name) {
  struct v4l2_queryctrl queryctrl;
  memset(&queryctrl, 0, sizeof(queryctrl));
  queryctrl.id = V4L2_CTRL_FLAG_NEXT_CTRL;
  while (ioctl(fd.get(), VIDIOC_QUERYCTRL, &queryctrl) == 0) {
    if (strncmp(reinterpret_cast<const char*>(queryctrl.name), name.c_str(),
                sizeof(queryctrl.name)) == 0) {
      return queryctrl.id;
    }
    queryctrl.id |= V4L2_CTRL_FLAG_NEXT_CTRL;
  }
  if (errno != EINVAL) {
    return ErrnoError()
           << "v4l2 VIDIOC_QUERYCTRL failed during control enumeration";
  }
  return std::nullopt;
}

Result<int64_t> CtrlValue(borrowed_fd fd, uint32_t ctrl_id) {
  struct v4l2_ext_control ext_ctrl;
  std::memset(&ext_ctrl, 0, sizeof(ext_ctrl));
  ext_ctrl.id = ctrl_id;

  struct v4l2_ext_controls ext_ctrls;
  std::memset(&ext_ctrls, 0, sizeof(ext_ctrls));
  ext_ctrls.which = V4L2_CTRL_WHICH_CUR_VAL;
  ext_ctrls.count = 1;
  ext_ctrls.controls = &ext_ctrl;

  if (ioctl(fd.get(), VIDIOC_G_EXT_CTRLS, &ext_ctrls) < 0) {
    return ErrnoError() << "ioctl(VIDIOC_G_EXT_CTRLS) failed for 0x" << std::hex
                        << ctrl_id;
  }

  return ext_ctrl.value64;
}

}  // namespace

Result<std::optional<int64_t>> LensFacingCtrl(borrowed_fd fd) {
  Result<std::optional<uint32_t>> ctrl_id = CtrlId(fd, "LENS_FACING");
  if (!ctrl_id.ok()) {
    return ctrl_id;
  }
  if (!ctrl_id.has_value()) {
    return ctrl_id;
  }
  return CtrlValue(fd, ctrl_id.value().value());
}

Result<std::string> DevNameToCameraId(const std::string& devName) {
  static const std::regex kDevicePathRE("/dev/video([0-9]+)");
  std::smatch sm;
  if (!std::regex_match(devName, sm, kDevicePathRE)) {
    return android::base::Error()
           << "Device name does not match expected format: " << devName;
  }
  int nodeIndex;
  if (!android::base::ParseInt(sm[1].str(), &nodeIndex)) {
    return android::base::Error()
           << "Failed to parse video node index from " << sm[1].str();
  }
  return std::to_string(nodeIndex - kVideoNodeIdOffset);
}

Result<std::string> CameraIdToDevName(const std::string& cameraId) {
  int id;
  if (!android::base::ParseInt(cameraId, &id)) {
    return android::base::Error() << "Failed to parse camera ID: " << cameraId;
  }
  if (id < 0) {
    return android::base::Error() << "Camera ID cannot be negative: " << id;
  }
  return "/dev/video" + std::to_string(id + kVideoNodeIdOffset);
}

}  // namespace virtio_media
}  // namespace cuttlefish
