#!/vendor/bin/sh

# Copyright 2024 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script is run right before Cuttlefish suspends the VM as part of taking
# a snapshot.

set -eux

/system/bin/cmd bluetooth_manager disable
/system/bin/cmd bluetooth_manager wait-for-state:STATE_OFF
/system/bin/cmd uwb disable-uwb

set +e
if /system/bin/cmd nfc status >/dev/null 2>&1; then
  /system/bin/cmd nfc disable-nfc

  # Poll until NFC is disabled (with 5s timeout)
  limit=50
  count=0
  while [ $count -lt $limit ]; do
    if /system/bin/cmd nfc status 2>/dev/null | grep -q "disabled"; then
      break
    fi
    sleep 0.1
    count=$((count + 1))
  done
fi
set -e


