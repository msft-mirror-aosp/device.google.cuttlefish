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

#pragma once

#include <ExternalCameraDeviceSession.h>
#include <ExternalCameraUtils.h>
#include <aidl/android/hardware/camera/common/Status.h>
#include <aidl/android/hardware/camera/device/BnCameraDeviceSession.h>
#include <aidl/android/hardware/camera/device/BufferRequest.h>
#include <aidl/android/hardware/camera/device/Stream.h>
#include <android-base/unique_fd.h>

#include <memory>
#include <vector>

namespace android {
namespace hardware {
namespace camera {
namespace device {
namespace implementation {

class VirtioMediaCameraDeviceSession
    : public aidl::android::hardware::camera::device::BnCameraDeviceSession {
 public:
  VirtioMediaCameraDeviceSession(
      const std::shared_ptr<
          aidl::android::hardware::camera::device::ICameraDeviceCallback>&
          callback,
      const android::hardware::camera::external::common::ExternalCameraConfig&
          cfg,
      const std::vector<SupportedV4L2Format>& sortedFormats,
      const CroppingType& croppingType,
      const common::V1_0::helper::CameraMetadata& chars,
      const std::string& cameraId, android::base::unique_fd v4l2Fd,
      v4l2_buf_type captureType);
  ~VirtioMediaCameraDeviceSession() override;

  bool isInitFailed();
  bool isClosed();

  ndk::ScopedAStatus close() override;

  ndk::ScopedAStatus configureStreams(
      const aidl::android::hardware::camera::device::StreamConfiguration&
          in_requestedConfiguration,
      std::vector<aidl::android::hardware::camera::device::HalStream>*
          _aidl_return) override;
  ndk::ScopedAStatus constructDefaultRequestSettings(
      aidl::android::hardware::camera::device::RequestTemplate in_type,
      aidl::android::hardware::camera::device::CameraMetadata* _aidl_return)
      override;
  ndk::ScopedAStatus flush() override;
  ndk::ScopedAStatus getCaptureRequestMetadataQueue(
      aidl::android::hardware::common::fmq::MQDescriptor<
          int8_t, aidl::android::hardware::common::fmq::SynchronizedReadWrite>*
          _aidl_return) override;
  ndk::ScopedAStatus getCaptureResultMetadataQueue(
      aidl::android::hardware::common::fmq::MQDescriptor<
          int8_t, aidl::android::hardware::common::fmq::SynchronizedReadWrite>*
          _aidl_return) override;
  ndk::ScopedAStatus isReconfigurationRequired(
      const aidl::android::hardware::camera::device::CameraMetadata&
          in_oldSessionParams,
      const aidl::android::hardware::camera::device::CameraMetadata&
          in_newSessionParams,
      bool* _aidl_return) override;
  ndk::ScopedAStatus processCaptureRequest(
      const std::vector<
          aidl::android::hardware::camera::device::CaptureRequest>& in_requests,
      const std::vector<aidl::android::hardware::camera::device::BufferCache>&
          in_cachesToRemove,
      int32_t* _aidl_return) override;
  ndk::ScopedAStatus signalStreamFlush(const std::vector<int32_t>& in_streamIds,
                                       int32_t in_streamConfigCounter) override;
  ndk::ScopedAStatus switchToOffline(
      const std::vector<int32_t>& in_streamsToKeep,
      aidl::android::hardware::camera::device::CameraOfflineSessionInfo*
          out_offlineSessionInfo,
      std::shared_ptr<
          aidl::android::hardware::camera::device::ICameraOfflineSession>*
          _aidl_return) override;
  ndk::ScopedAStatus repeatingRequestEnd(
      int32_t in_frameNumber,
      const std::vector<int32_t>& in_streamIds) override;

  binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;

 private:
  std::shared_ptr<ExternalCameraDeviceSession> mSession;
};

}  // namespace implementation
}  // namespace device
}  // namespace camera
}  // namespace hardware
}  // namespace android
