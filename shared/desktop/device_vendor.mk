#
# Copyright (C) 2024 The Android Open Source Project
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

PRODUCT_MANIFEST_FILES += device/google/cuttlefish/shared/config/product_manifest.xml
SYSTEM_EXT_MANIFEST_FILES += device/google/cuttlefish/shared/config/system_ext_manifest.xml

# Extend cuttlefish common sepolicy with desktop-specific functionality.
BOARD_SEPOLICY_DIRS += device/google/cuttlefish/shared/desktop/sepolicy
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/google/cuttlefish/shared/desktop/sepolicy/system_ext/private

$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_vendor.mk)

$(call inherit-product, frameworks/native/build/tablet-7in-xhdpi-2048-dalvik-heap.mk)
$(call inherit-product, device/google/cuttlefish/shared/bluetooth/device_vendor.mk)
$(call inherit-product, device/google/cuttlefish/shared/gnss/device_vendor.mk)
$(call inherit-product, device/google/cuttlefish/shared/graphics/device_vendor.mk)
$(call inherit-product, device/google/cuttlefish/shared/reboot_escrow/device_vendor.mk)
$(call inherit-product, device/google/cuttlefish/shared/secure_element/device_vendor.mk)
$(call inherit-product, device/google/cuttlefish/shared/swiftshader/device_vendor.mk)
$(call inherit-product, device/google/cuttlefish/shared/sensors/device_vendor.mk)
$(call inherit-product, device/google/cuttlefish/shared/virgl/device_vendor.mk)
$(call inherit-product, device/google/cuttlefish/shared/device.mk)

# Loads the camera HAL and which set of cameras is required.
$(call inherit-product, device/google/cuttlefish/shared/camera/device_vendor.mk)
$(call inherit-product, device/google/cuttlefish/shared/camera/config/standard.mk)
