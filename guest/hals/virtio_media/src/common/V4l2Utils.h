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

#include <optional>

#include <android-base/result.h>
#include <android-base/unique_fd.h>

using ::android::base::borrowed_fd;
using ::android::base::Result;

namespace cuttlefish {
namespace virtio_media {

// Queries virtio-media "lens_facing" control value.
Result<std::optional<int64_t>> LensFacingCtrl(borrowed_fd fd);

}  // namespace virtio_media
}  // namespace cuttlefish
