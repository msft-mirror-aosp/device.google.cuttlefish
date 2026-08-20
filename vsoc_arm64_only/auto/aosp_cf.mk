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


# CF targets set the ro.hw_timeout_multiplier property in the init script using the value
# specified on the command line in assemble_cvd
# NOTE: This must be set before inheriting car_generic_system.mk
USE_DEFAULT_HW_TIMEOUT_MULTIPLIER?=false

ifeq ($(RELEASE_CAR_SDV_ENABLE_INTEGRATION),true)
    # NOTE: This must be set before inheriting car_generic_system.mk to allow the
    # inclusion of SDV components that go to system image
    ENABLE_SDV_INTEGRATION ?= true
endif

#
# All components inherited here go to system image
#
$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
$(call inherit-product, packages/services/Car/car_product/build/car_generic_system.mk)

# FIXME: generic_system.mk sets 'PRODUCT_ENFORCE_RRO_TARGETS := *'
#        but this breaks phone_car. So undo it here.
PRODUCT_ENFORCE_RRO_TARGETS := frameworks-res

PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := true

#
# All components inherited here go to system_ext image
#
$(call inherit-product, packages/services/Car/car_product/build/car_system_ext.mk)

#
# All components inherited here go to product image
#
$(call inherit-product, packages/services/Car/car_product/build/car_product.mk)

#
# All components inherited here go to vendor image
#
$(call inherit-product, device/google/cuttlefish/shared/auto/device_vendor.mk)

# Use vsock as VHAL transport to align with on-device deployment
ENABLE_AUTO_ETHERNET ?= false

# Fall back to the default sensor HAL
LOCAL_SENSOR_PRODUCT_PACKAGE := com.android.hardware.sensors

#
# Special settings for the target
#
$(call inherit-product, device/google/cuttlefish/vsoc_arm64/bootloader.mk)

# Exclude features that are not available on AOSP devices.
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/aosp_excluded_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/aosp_excluded_hardware.xml

PRODUCT_NAME := aosp_cf_arm64_auto
PRODUCT_DEVICE := vsoc_arm64_only
PRODUCT_MANUFACTURER := Google
PRODUCT_MODEL := Cuttlefish arm64 auto

PRODUCT_VENDOR_PROPERTIES += \
    ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
    ro.soc.model=$(PRODUCT_DEVICE)

# SDV components that don't go to system image
ifeq ($(ENABLE_SDV_INTEGRATION),true)
    $(call inherit-product, device/google/sdv/sdv_ivi/sdv_ivi.mk)
endif
