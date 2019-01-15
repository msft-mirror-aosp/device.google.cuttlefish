#
# Copyright (C) 2017 The Android Open Source Project
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

$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
$(call inherit-product, device/google/cuttlefish/shared/phone/device.mk)

PRODUCT_NAME := aosp_cf_x86_64_pasan
PRODUCT_DEVICE := vsoc_x86_64
PRODUCT_MODEL := Cuttlefish x86_64 ASAN phone
# Intentionally points to phone overlay to avoid code duplication
PRODUCT_PACKAGE_OVERLAYS := device/google/cuttlefish/vsoc_x86_64/phone/overlay
