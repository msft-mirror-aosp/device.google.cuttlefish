/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "suspend_blocker"

#include <sys/types.h>
#include <sys/stat.h>

#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include <cstring>

#include <log/log.h>

int main() {
    int wake_lock_fd = open("/sys/power/wake_lock", O_RDWR | O_CLOEXEC);
    if (!wake_lock_fd) {
        ALOGE("Couldn't open /sys/power/wake_lock");
        return -1;
    }

    const char* WAKE_LOCK_ID = "suspend_blocker";
    long lock_name_len = strlen(WAKE_LOCK_ID);
    if (write(wake_lock_fd, WAKE_LOCK_ID, lock_name_len) == -1) {
        ALOGE("Couldn't write to /sys/power/wake_lock");
        return -2;
    }

    sigset_t mask;
    sigemptyset(&mask);
    return sigsuspend(&mask);  // Infinite sleep
}
