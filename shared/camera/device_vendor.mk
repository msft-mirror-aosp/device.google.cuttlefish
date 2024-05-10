#
# Copyright (C) 2022 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Enable Camera Extension sample
ifeq ($(TARGET_USE_CAMERA_ADVANCED_EXTENSION_SAMPLE),true)
PRODUCT_PACKAGES += \
    androidx.camera.extensions.impl.advanced advancedSample_camera_extensions.xml \
    libencoderjpeg_jni

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/app/EyesFreeVidService/EyesFreeVidService.apk

PRODUCT_PACKAGES += EyesFreeVidService

PRODUCT_VENDOR_PROPERTIES += \
    ro.vendor.camera.extensions.package=android.camera.extensions.impl.service \
    ro.vendor.camera.extensions.service=android.camera.extensions.impl.service.EyesFreeVidService
else
PRODUCT_PACKAGES += androidx.camera.extensions.impl sample_camera_extensions.xml
endif

PRODUCT_SOONG_NAMESPACES += hardware/google/camera
PRODUCT_SOONG_NAMESPACES += hardware/google/camera/devices/EmulatedCamera

# TODO(b/257379485): 3A is incrementally enabling cuttlefish build for native
# code coverage support, temporary require separate namespace for folders that
# can be built successfully.
PRODUCT_SOONG_NAMESPACES += vendor/google/camera/common/g3_shared
PRODUCT_SOONG_NAMESPACES += vendor/google/camera/google_3a/libs_v4/g3ABase
PRODUCT_SOONG_NAMESPACES += vendor/google/camera/google_3a/libs_v4/gABC/native_coverage
PRODUCT_SOONG_NAMESPACES += vendor/google/camera/google_3a/libs_v4/gAF
PRODUCT_SOONG_NAMESPACES += vendor/google/camera/google_3a/libs_v4/gafd
PRODUCT_SOONG_NAMESPACES += vendor/google/camera/google_3a/libs_v4/gHAWB/native_coverage

# go/lyric-soong-variables
$(call soong_config_set,lyric,camera_hardware,cuttlefish)
$(call soong_config_set,lyric,tuning_product,cuttlefish)
$(call soong_config_set,google3a_config,target_device,cuttlefish)

ifeq ($(TARGET_USE_VSOCK_CAMERA_HAL_IMPL),true)
PRODUCT_PACKAGES += \
    android.hardware.camera.provider@2.7-external-vsock-service \
    android.hardware.camera.provider@2.7-impl-cuttlefish
DEVICE_MANIFEST_FILE += \
    device/google/cuttlefish/guest/hals/camera/manifest.xml
else
PRODUCT_PACKAGES += com.google.emulated.camera.provider.hal
PRODUCT_PACKAGES += com.google.emulated.camera.provider.hal.fastscenecycle
endif
