/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <android-base/logging.h>
#include <errno.h>
#include <log/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fstream>

#include <cutils/properties.h>
#include <gflags/gflags.h>

#include "common/libs/fs/shared_fd.h"
#include "common/libs/utils/subprocess.h"

static const char TOMBSTONE_DIR[] = "/data/tombstones/";

// returns a fd which when read from, provides inotify events when tombstones
// are created
static int new_tombstone_create_notifier(void) {
  int file_create_notification_handle = inotify_init();
  if (file_create_notification_handle == -1) {
    ALOGE("%s: inotify_init failure error: '%s' (%d)", __FUNCTION__,
      strerror(errno), errno);
    return -1;
  }

  int watch_descriptor = inotify_add_watch(file_create_notification_handle,
    TOMBSTONE_DIR, IN_CREATE);
  if (watch_descriptor == -1) {
    ALOGE("%s: Could not add watch for '%s', error: '%s' (%d)", __FUNCTION__,
      TOMBSTONE_DIR, strerror(errno), errno);
    close(file_create_notification_handle);
    return -1;
  }

  return file_create_notification_handle;
}

#define INOTIFY_MAX_EVENT_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)
static std::vector<std::string> get_next_tombstones_path_blocking(int fd) {
  char event_readout[INOTIFY_MAX_EVENT_SIZE];
  int bytes_parsed = 0;
  std::vector<std::string> tombstone_paths;
  // Each successful read can contain one or more of inotify_event events
  // Note: read() on inotify returns 'whole' events, will never partially
  // populate the buffer.
  int event_read_out_length = read(fd, event_readout, INOTIFY_MAX_EVENT_SIZE);

  if(event_read_out_length == -1) {
    ALOGE("%s: Couldn't read out inotify event due to error: '%s' (%d)",
      __FUNCTION__, strerror(errno), errno);
    return std::vector<std::string>();
  }

  while (bytes_parsed < event_read_out_length) {
    struct inotify_event* event =
        reinterpret_cast<inotify_event*>(event_readout + bytes_parsed);
    bytes_parsed += sizeof(struct inotify_event) + event->len;

    // No file name was present
    if (event->len == 0) {
      ALOGE("%s: inotify event didn't contain filename", __FUNCTION__);
      continue;
    }
    if (!(event->mask & IN_CREATE)) {
      ALOGE("%s: inotify event didn't pertain to file creation", __FUNCTION__);
      continue;
    }
    tombstone_paths.push_back(std::string(TOMBSTONE_DIR) +
                              std::string(event->name));
  }

  return tombstone_paths;
}

DEFINE_uint32(port,
              static_cast<uint32_t>(
                  property_get_int64("ro.boot.vsock_tombstone_port", 0)),
              "VSOCK port to send tombstones to");
DEFINE_uint32(cid, 2, "VSOCK CID to send logcat output to");
#define TOMBSTONE_BUFFER_SIZE (1024)

int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  if(FLAGS_port == 0) {
    LOG(FATAL_WITHOUT_ABORT) << "Port flag is required";
    while(1) {sleep(1);};
  }

  int file_create_notification_handle = new_tombstone_create_notifier();
  if (file_create_notification_handle == -1) {return -1;}

  LOG(INFO) << "tombstone watcher successfully initialized";

  while (true) {
    std::vector<std::string> ts_paths =
        get_next_tombstones_path_blocking(file_create_notification_handle);
    for (auto& ts_path : ts_paths) {
      auto log_fd =
          cuttlefish::SharedFD::VsockClient(FLAGS_cid, FLAGS_port, SOCK_STREAM);
      std::ifstream ifs(ts_path);
      char buffer[TOMBSTONE_BUFFER_SIZE];
      uint num_transfers = 0;
      int num_bytes_read = 0;
      while (log_fd->IsOpen() && ifs.is_open() && !ifs.eof()) {
        ifs.read(buffer, sizeof(buffer));
        num_bytes_read += ifs.gcount();
        log_fd->Write(buffer, ifs.gcount());
        num_transfers++;
      }

      if (!log_fd->IsOpen()) {
        auto error = log_fd->StrError();
        ALOGE("Unable to connect to vsock:%u:%u: %s", FLAGS_cid, FLAGS_port,
              error.c_str());
      } else if (!ifs.is_open()) {
        ALOGE("%s closed in the middle of readout.", ts_path.c_str());
      } else {
        LOG(INFO) << num_bytes_read << " chars transferred from "
                  << ts_path.c_str() << " over " << num_transfers << " "
                  << TOMBSTONE_BUFFER_SIZE << " byte sized transfers";
      }
    }
  }

  return 0;
}
