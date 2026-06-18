#!/system/bin/sh

# TODO(b/355193455): Quit using the workaround `timeout`.
timeout 1 cmd wifi set-wifi-enabled enabled
timeout 1 cmd wifi connect-network VirtWifi open
