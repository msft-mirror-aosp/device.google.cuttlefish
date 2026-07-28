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

#define LOG_TAG "VirtioMediaCamDevSsn"

#include "VirtioMediaCameraDeviceSession.h"

#include <convert.h>
#include <log/log.h>

namespace android {
namespace hardware {
namespace camera {
namespace device {
namespace implementation {

using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::BnCameraDeviceSession;
using ::aidl::android::hardware::camera::device::BufferCache;
using ::aidl::android::hardware::camera::device::CameraMetadata;
using ::aidl::android::hardware::camera::device::CameraOfflineSessionInfo;
using ::aidl::android::hardware::camera::device::CaptureRequest;
using ::aidl::android::hardware::camera::device::HalStream;
using ::aidl::android::hardware::camera::device::ICameraDeviceCallback;
using ::aidl::android::hardware::camera::device::ICameraOfflineSession;
using ::aidl::android::hardware::camera::device::RequestTemplate;
using ::aidl::android::hardware::camera::device::StreamConfiguration;
using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::android::base::unique_fd;
using ::android::hardware::camera::external::common::ExternalCameraConfig;
using ::ndk::ScopedAStatus;

VirtioMediaCameraDeviceSession::VirtioMediaCameraDeviceSession(
    const std::shared_ptr<ICameraDeviceCallback>& callback,
    const ExternalCameraConfig& cfg,
    const std::vector<SupportedV4L2Format>& sortedFormats,
    const CroppingType& croppingType,
    const common::V1_0::helper::CameraMetadata& chars,
    const std::string& cameraId, unique_fd v4l2Fd, v4l2_buf_type captureType)
    : mSession(ndk::SharedRefBase::make<ExternalCameraDeviceSession>(
          callback, cfg, sortedFormats, croppingType, chars, cameraId,
          std::move(v4l2Fd), captureType)) {}

VirtioMediaCameraDeviceSession::~VirtioMediaCameraDeviceSession() {}

bool VirtioMediaCameraDeviceSession::isInitFailed() {
  if (mSession == nullptr) {
    return true;
  }
  return mSession->isInitFailed();
}

bool VirtioMediaCameraDeviceSession::isClosed() {
  if (mSession == nullptr) {
    return true;
  }
  return mSession->isClosed();
}

ScopedAStatus VirtioMediaCameraDeviceSession::close() {
  if (mSession == nullptr) {
    return ScopedAStatus::ok();
  }
  return mSession->close();
}

ScopedAStatus VirtioMediaCameraDeviceSession::configureStreams(
    const StreamConfiguration& in_requestedConfiguration,
    std::vector<HalStream>* _aidl_return) {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  return mSession->configureStreams(in_requestedConfiguration, _aidl_return);
}

ScopedAStatus VirtioMediaCameraDeviceSession::constructDefaultRequestSettings(
    RequestTemplate in_type, CameraMetadata* _aidl_return) {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  ScopedAStatus res;
  if (in_type == RequestTemplate::MANUAL) {
    // Use PREVIEW defaults as the baseline for MANUAL template.
    res = mSession->constructDefaultRequestSettings(RequestTemplate::PREVIEW,
                                                    _aidl_return);
  } else {
    res = mSession->constructDefaultRequestSettings(in_type, _aidl_return);
  }

  if (!res.isOk()) {
    return res;
  }

  ::android::hardware::camera::common::V1_0::helper::CameraMetadata tmp;
  tmp =
      reinterpret_cast<const camera_metadata_t*>(_aidl_return->metadata.data());

  if (in_type == RequestTemplate::MANUAL) {
    // Per camera3.h specification for CAMERA3_TEMPLATE_MANUAL:
    // "All automatic control is disabled (auto-exposure, auto-white balance,
    // auto-focus)..."
    uint8_t intent = ANDROID_CONTROL_CAPTURE_INTENT_MANUAL;
    uint8_t controlMode = ANDROID_CONTROL_MODE_OFF;
    uint8_t aeMode = ANDROID_CONTROL_AE_MODE_OFF;
    uint8_t awbMode = ANDROID_CONTROL_AWB_MODE_OFF;

    tmp.update(ANDROID_CONTROL_CAPTURE_INTENT, &intent, 1);
    tmp.update(ANDROID_CONTROL_MODE, &controlMode, 1);
    tmp.update(ANDROID_CONTROL_AE_MODE, &aeMode, 1);
    tmp.update(ANDROID_CONTROL_AWB_MODE, &awbMode, 1);
  }

  // android.noiseReduction.mode
  uint8_t noiseReductionMode = ANDROID_NOISE_REDUCTION_MODE_FAST;
  if (in_type == RequestTemplate::STILL_CAPTURE) {
    noiseReductionMode = ANDROID_NOISE_REDUCTION_MODE_HIGH_QUALITY;
  } else if (in_type == RequestTemplate::MANUAL) {
    noiseReductionMode = ANDROID_NOISE_REDUCTION_MODE_OFF;
  }
  tmp.update(ANDROID_NOISE_REDUCTION_MODE, &noiseReductionMode, 1);

  // android.control.aeTargetFpsRange
  // For video recording templates, the default target FPS range must be fixed
  // (minFps == maxFps) to ensure stable frame delivery for video encoders.
  if (in_type == RequestTemplate::VIDEO_RECORD) {
    camera_metadata_entry fpsRangeEntry =
        tmp.find(ANDROID_CONTROL_AE_TARGET_FPS_RANGE);
    if (fpsRangeEntry.count == 2) {
      int32_t maxFps = fpsRangeEntry.data.i32[1];
      int32_t fixedFpsRange[] = {maxFps, maxFps};
      tmp.update(ANDROID_CONTROL_AE_TARGET_FPS_RANGE, fixedFpsRange, 2);
    } else {
      ALOGE(
          "%s: Target FPS range is missing or malformed in default record "
          "template (count=%zu)",
          __FUNCTION__, fpsRangeEntry.count);
    }
  }

  const camera_metadata_t* md = tmp.getAndLock();
  convertToAidl(md, _aidl_return);
  tmp.unlock(md);

  return ScopedAStatus::ok();
}

ScopedAStatus VirtioMediaCameraDeviceSession::flush() {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  return mSession->flush();
}

ScopedAStatus VirtioMediaCameraDeviceSession::getCaptureRequestMetadataQueue(
    MQDescriptor<int8_t, SynchronizedReadWrite>* _aidl_return) {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  return mSession->getCaptureRequestMetadataQueue(_aidl_return);
}

ScopedAStatus VirtioMediaCameraDeviceSession::getCaptureResultMetadataQueue(
    MQDescriptor<int8_t, SynchronizedReadWrite>* _aidl_return) {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  return mSession->getCaptureResultMetadataQueue(_aidl_return);
}

ScopedAStatus VirtioMediaCameraDeviceSession::isReconfigurationRequired(
    const CameraMetadata& in_oldSessionParams,
    const CameraMetadata& in_newSessionParams, bool* _aidl_return) {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  return mSession->isReconfigurationRequired(in_oldSessionParams,
                                             in_newSessionParams, _aidl_return);
}

ScopedAStatus VirtioMediaCameraDeviceSession::processCaptureRequest(
    const std::vector<CaptureRequest>& in_requests,
    const std::vector<BufferCache>& in_cachesToRemove, int32_t* _aidl_return) {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  return mSession->processCaptureRequest(in_requests, in_cachesToRemove,
                                         _aidl_return);
}

ScopedAStatus VirtioMediaCameraDeviceSession::signalStreamFlush(
    const std::vector<int32_t>& in_streamIds, int32_t in_streamConfigCounter) {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  return mSession->signalStreamFlush(in_streamIds, in_streamConfigCounter);
}

ScopedAStatus VirtioMediaCameraDeviceSession::switchToOffline(
    const std::vector<int32_t>& in_streamsToKeep,
    CameraOfflineSessionInfo* out_offlineSessionInfo,
    std::shared_ptr<ICameraOfflineSession>* _aidl_return) {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  return mSession->switchToOffline(in_streamsToKeep, out_offlineSessionInfo,
                                   _aidl_return);
}

ScopedAStatus VirtioMediaCameraDeviceSession::repeatingRequestEnd(
    int32_t in_frameNumber, const std::vector<int32_t>& in_streamIds) {
  if (mSession == nullptr) {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::INTERNAL_ERROR));
  }
  return mSession->repeatingRequestEnd(in_frameNumber, in_streamIds);
}

binder_status_t VirtioMediaCameraDeviceSession::dump(int fd, const char** args,
                                                     uint32_t numArgs) {
  if (mSession == nullptr) {
    return STATUS_OK;
  }
  return mSession->dump(fd, args, numArgs);
}

}  // namespace implementation
}  // namespace device
}  // namespace camera
}  // namespace hardware
}  // namespace android
