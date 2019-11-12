LOCAL_PATH := $(call my-dir)

cvd_host_package_tar := $(HOST_OUT)/cvd-host_package.tar.gz

.PHONY: hosttar
hosttar: $(cvd_host_package_tar)

$(cvd_host_package_tar): PRIVATE_TAR_FORMAT :=
ifeq ($(HOST_OS),linux)
$(cvd_host_package_tar): PRIVATE_TAR_FORMAT := --format=gnu
endif

# Build this by default when a developer types make
droidcore: $(cvd_host_package_tar)

# Build and store them on the build server.
$(call dist-for-goals, dist_files, $(cvd_host_package_tar))

bin_path := $(notdir $(HOST_OUT_EXECUTABLES))
lib_path := $(notdir $(HOST_OUT_SHARED_LIBRARIES))
tests_path := $(notdir $(HOST_OUT_NATIVE_TESTS))
x86_64_seccomp_files_path := usr/share/cuttlefish/x86_64-linux-gnu/seccomp

cvd_host_executables := \
    adb \
    adbshell \
    host_region_e2e_test \
    launch_cvd \
    socket_forward_proxy \
    socket_vsock_proxy \
    adb_connector \
    stop_cvd \
    vnc_server \
    record_audio \
    cf_qemu.sh \
    cf_bpttool \
    kernel_log_monitor \
    extract-vmlinux \
    crosvm \
    aarch64-linux-gnu/crosvm \
    aarch64-linux-gnu/libepoxy.so.0 \
    aarch64-linux-gnu/libgbm.so.1 \
    aarch64-linux-gnu/libminijail.so \
    aarch64-linux-gnu/libvirglrenderer.so.1 \
    x86_64-linux-gnu/crosvm \
    x86_64-linux-gnu/libepoxy.so.0 \
    x86_64-linux-gnu/libgbm.so.1 \
    x86_64-linux-gnu/libminijail.so \
    x86_64-linux-gnu/libvirglrenderer.so.1 \
    x86_64-linux-gnu/libc++.so.1 \
    x86_64-linux-gnu/libandroid-emu-shared.so \
    x86_64-linux-gnu/libemugl_common.so \
    x86_64-linux-gnu/libOpenglRender.so \
    x86_64-linux-gnu/libEGL_translator.so \
    x86_64-linux-gnu/libGLES_CM_translator.so \
    x86_64-linux-gnu/libGLES_V2_translator.so \
    x86_64-linux-gnu/libgfxstream_backend.so \
    logcat_receiver \
    config_server \
    tombstone_receiver \
    console_forwarder \

cvd_host_tests := \
    auto_free_buffer_test \
    circqueue_test \
    cuttlefish_thread_test \
    hald_client_test \
    lock_test \
    monotonic_time_test \
    vsoc_graphics_test \
    cuttlefish_net_tests \

cvd_host_shared_libraries := \
    libbase.so \
    vsoc_lib.so \
    libcuttlefish_fs.so \
    cuttlefish_auto_resources.so \
    libcuttlefish_strings.so \
    libcuttlefish_utils.so \
    cuttlefish_tcp_socket.so \
    cuttlefish_net.so \
    liblog.so \
    libnl.so \
    libc++.so \
    libz-host.so \
    libicuuc-host.so \
    libcuttlefish_device_config.so \
    cdisk_spec.so \
    libprotobuf-cpp-full.so \


cvd_host_configs := \
    system-root.dtb \
    composite-system-root.dtb \
    gsi.fstab \
    composite-gsi.fstab \
    composite-gsi-arm64.fstab \

x86_64_seccomp_files := \
    9p_device.policy \
    balloon_device.policy \
    block_device.policy \
    common_device.policy \
    cras_audio_device.policy \
    fs_device.policy \
    gpu_device.policy \
    input_device.policy \
    net_device.policy \
    null_audio_device.policy \
    pmem_device.policy \
    rng_device.policy \
    serial.policy \
    tpm_device.policy \
    vfio_device.policy \
    vhost_net_device.policy \
    vhost_vsock_device.policy \
    wl_device.policy \
    xhci.policy \

cvd_host_package_files := \
     $(addprefix config/,$(cvd_host_configs)) \
     $(addprefix $(bin_path)/,$(cvd_host_executables)) \
     $(addprefix $(lib_path)/,$(cvd_host_shared_libraries)) \
     $(foreach test,$(cvd_host_tests), ${tests_path}/$(test)/$(test)) \
     $(addprefix $(x86_64_seccomp_files_path)/,$(x86_64_seccomp_files)) \

$(cvd_host_package_tar): PRIVATE_FILES := $(cvd_host_package_files)
$(cvd_host_package_tar): $(addprefix $(HOST_OUT)/,$(cvd_host_package_files))
	$(hide) rm -rf $@ && tar Scfz $@.tmp -C $(HOST_OUT) $(PRIVATE_TAR_FORMAT) $(PRIVATE_FILES)
	$(hide) mv $@.tmp $@
