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

#ifndef ANDROID_C2_CUTTLEFISH_HEVC_DEC_H_
#define ANDROID_C2_CUTTLEFISH_HEVC_DEC_H_

#include <inttypes.h>
#include <atomic>

#include <C2ComponentFactory.h>
#include <SimpleC2Component.h>
#include <ihevc_defs.h>
#include <ihevc_typedefs.h>
#include <ihevcd_cxa.h>
#include <media/stagefright/foundation/ColorUtils.h>
#include <util/C2InterfaceHelper.h>

namespace android {

struct C2CuttlefishHevcDec : public SimpleC2Component {
  class IntfImpl;

  C2CuttlefishHevcDec(const char* name, c2_node_id_t id,
                      const std::shared_ptr<IntfImpl>& intfImpl);
  C2CuttlefishHevcDec(const char* name, c2_node_id_t id,
                      const std::shared_ptr<C2ReflectorHelper>& helper);
  virtual ~C2CuttlefishHevcDec();

  // From SimpleC2Component
  c2_status_t onInit() override;
  c2_status_t onStop() override;
  void onReset() override;
  void onRelease() override;
  c2_status_t onFlush_sm() override;
  void process(const std::unique_ptr<C2Work>& work,
               const std::shared_ptr<C2BlockPool>& pool) override;
  c2_status_t drain(uint32_t drainMode,
                    const std::shared_ptr<C2BlockPool>& pool) override;

 private:
  status_t createDecoder();
  status_t setNumCores();
  status_t setParams(size_t stride, IVD_VIDEO_DECODE_MODE_T dec_mode);
  status_t getVersion();
  status_t initDecoder();
  bool setDecodeArgs(ivd_video_decode_ip_t* ps_decode_ip,
                     ivd_video_decode_op_t* ps_decode_op, C2ReadView* inBuffer,
                     C2GraphicView* outBuffer, size_t inOffset, size_t inSize,
                     uint32_t tsMarker);
  bool getVuiParams();
  c2_status_t ensureDecoderState(const std::shared_ptr<C2BlockPool>& pool);
  void finishWork(uint64_t index, const std::unique_ptr<C2Work>& work);
  status_t setFlushMode();
  c2_status_t drainInternal(uint32_t drainMode,
                            const std::shared_ptr<C2BlockPool>& pool,
                            const std::unique_ptr<C2Work>& work);
  status_t resetDecoder();
  void resetPlugin();
  status_t deleteDecoder();

  // TODO:This is not the right place for this enum. These should
  // be part of c2-vndk so that they can be accessed by all video plugins
  // until then, make them feel at home
  enum {
    kNotSupported,
    kPreferBitstream,
    kPreferContainer,
  };

  std::shared_ptr<IntfImpl> mIntf;
  iv_obj_t* mDecHandle;
  std::shared_ptr<C2GraphicBlock> mOutBlock;
  uint8_t* mOutBufferFlush;

  size_t mNumCores;
  IV_COLOR_FORMAT_T mIvColorformat;
  uint32_t mOutputDelay;
  uint32_t mWidth;
  uint32_t mHeight;
  uint32_t mStride;
  bool mSignalledOutputEos;
  bool mSignalledError;
  bool mHeaderDecoded;
  std::atomic_uint64_t mOutIndex;

  // Color aspects. These are ISO values and are meant to detect changes in
  // aspects to avoid converting them to C2 values for each frame
  struct VuiColorAspects {
    uint8_t primaries;
    uint8_t transfer;
    uint8_t coeffs;
    uint8_t fullRange;

    // default color aspects
    VuiColorAspects() : primaries(2), transfer(2), coeffs(2), fullRange(0) {}

    bool operator==(const VuiColorAspects& o) const {
      return primaries == o.primaries && transfer == o.transfer &&
             coeffs == o.coeffs && fullRange == o.fullRange;
    }
  } mBitstreamColorAspects;

  // profile
  nsecs_t mTimeStart = 0;
  nsecs_t mTimeEnd = 0;

  C2_DO_NOT_COPY(C2CuttlefishHevcDec);
};

class CuttlefishComponentStore;

std::shared_ptr<C2ComponentFactory> CreateCuttlefishHevcFactory(
    const std::shared_ptr<C2ReflectorHelper>& helper);

void RegisterCuttlefishHevcDec(
    CuttlefishComponentStore* store,
    const std::shared_ptr<C2ReflectorHelper>& helper);

}  // namespace android

#endif  // ANDROID_C2_CUTTLEFISH_HEVC_DEC_H_
