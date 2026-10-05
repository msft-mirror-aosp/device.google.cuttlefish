# LiteRT Mock Dispatch Prebuilts for Cuttlefish

This directory contains prebuilt binaries of the LiteRT Mock Dispatch library (`liblitert_dispatch_mock.so`) used by Cuttlefish virtual devices to simulate NPU execution in the `android.hardware.npu` execution HAL.

## Overview

The `liblitert_dispatch_mock` library implements the LiteRT Dispatch C API (`LiteRtDispatchApi`) using CPU execution via TensorFlow Lite and the XNNPACK delegate. It enables Cuttlefish to execute NPU models and run CTS / VTS tests without requiring physical NPU hardware.

## Prebuilt Versioning

Prebuilts are organized by date-stamped snapshot directories under `prebuilts/<YYYYMMDD>/`:

```
npu/
├── Android.bp
├── README.md
├── prebuilts/
│   └── 20260828/
│       ├── arm64/
│       │   └── liblitert_dispatch_mock.so
│       ├── x86/
│       │   └── liblitert_dispatch_mock.so
│       └── x86_64/
│           └── liblitert_dispatch_mock.so
└── testdata/
    ├── TestMobileNetV2.inp
    ├── TestMobileNetV2.out.ref
    ├── TestMobileNetV2.textproto
    └── TestMobileNetV2.tflite
```

When dropping a new prebuilt:
1. Create a new directory under `prebuilts/` named with the drop date (`YYYYMMDD`).
2. Place the built `arm64`, `x86`, and `x86_64` `.so` files into their respective subdirectories.
3. Update `device/google/cuttlefish/npu/Android.bp` to point to the new versioned paths.

---

## Building from Google3 Source

The mock dispatch library is built from Google3 using Blaze.

### Build Requirements & Options

When building for the `/vendor` partition in Android, specific build options are required:

1. **`--define=litert_android_no_jni=true`**:
   - **Crucial for `/vendor` compatibility**: By default, LiteRT links against `libandroid.so` for `AHardwareBuffer` APIs. However, `libandroid.so` is part of the system/platform SDK and is not accessible on the `/vendor` partition.
   - Passing `--define=litert_android_no_jni=true` switches LiteRT to link against `libnativewindow.so` directly, making the resulting binary compatible with `/vendor` shared library restrictions.

2. **`--android_ndk_min_sdk_version=29`**:
   - Sets the NDK minimum API level to 29 (Android 10) to ensure API compatibility.

3. **`--config=android_x86_64` / `--config=android_x86` / `--config=android_arm64`**:
   - Selects the target architecture toolchain.

4. **`-c opt`**:
   - Enables compiler optimizations.

---

### Step-by-Step Build Instructions

1. From a Google3 workspace (e.g. in Citc / Fig):

```bash
# 1. Build for x86_64 (Cuttlefish x86_64 target)
blaze build -c opt \
  --config=android_x86_64 \
  --android_ndk_min_sdk_version=29 \
  --define=litert_android_no_jni=true \
  //third_party/odml/litert/litert/runtime/dispatch/mock:LiteRtDispatchMock

# 2. Copy the x86_64 binary to the prebuilts directory:
cp blaze-bin/third_party/odml/litert/litert/runtime/dispatch/mock/libLiteRtDispatchMock.so \
  <android_root>/device/google/cuttlefish/npu/prebuilts/<VERSION>/x86_64/liblitert_dispatch_mock.so

# 3. Build for x86 (Cuttlefish 32-bit x86 target)
blaze build -c opt \
  --config=android_x86 \
  --android_ndk_min_sdk_version=29 \
  --define=litert_android_no_jni=true \
  //third_party/odml/litert/litert/runtime/dispatch/mock:LiteRtDispatchMock

# 4. Copy the x86 binary to the prebuilts directory:
cp blaze-bin/third_party/odml/litert/litert/runtime/dispatch/mock/libLiteRtDispatchMock.so \
  <android_root>/device/google/cuttlefish/npu/prebuilts/<VERSION>/x86/liblitert_dispatch_mock.so

# 5. Build for arm64 (Cuttlefish arm64 target)
blaze build -c opt \
  --config=android_arm64 \
  --android_ndk_min_sdk_version=29 \
  --define=litert_android_no_jni=true \
  //third_party/odml/litert/litert/runtime/dispatch/mock:LiteRtDispatchMock

# 6. Copy the arm64 binary to the prebuilts directory:
cp blaze-bin/third_party/odml/litert/litert/runtime/dispatch/mock/libLiteRtDispatchMock.so \
  <android_root>/device/google/cuttlefish/npu/prebuilts/<VERSION>/arm64/liblitert_dispatch_mock.so
```

2. Verify dynamic dependencies with `readelf`:

```bash
readelf -d liblitert_dispatch_mock.so | grep NEEDED
```

Ensure `libandroid.so` is **not** present in `NEEDED` entries. Only vendor-accessible libraries (such as `libdl.so`, `libnativewindow.so`, `libGLESv3.so`, `libEGL.so`, `libm.so`, `liblog.so`, `libc.so`) should be linked.

---

## Verification

After updating the prebuilts:

1. Build and sync to Cuttlefish:
```bash
build_sdk build '{"targets": ["sync", "liblitert_dispatch_mock", "android.hardware.npu-service.litert", "VtsHalNpuTargetTest"]}'
adevice update
```

2. Run the NPU VTS test suite:
```bash
atest VtsHalNpuTargetTest
```
