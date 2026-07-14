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

# Enabling fullaccess for clients to omapi in cuttlefish
PRODUCT_PRODUCT_PROPERTIES += \
    persist.service.seek=fullaccess

PRODUCT_COPY_FILES += \
    device/google/cuttlefish/shared/omapi/hal_uuid_map_config.xml:$(TARGET_COPY_OUT_VENDOR)/etc/hal_uuid_map_config.xml
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/android.hardware.se.omapi.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.se.omapi.ese.xml

# Enable Native Rust OMAPI (Note: SecureElement Java app remains in the build but is inactive at runtime)
PRODUCT_PACKAGES += omapi
PRODUCT_PRODUCT_PROPERTIES += persist.sys.secure_element.backend=rust
