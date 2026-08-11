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
#include <map>
#include <memory>
#include <vector>

#include <C2Component.h>
#include <C2ComponentFactory.h>
#include <C2Config.h>
#include <util/C2InterfaceHelper.h>

namespace android {

class CuttlefishComponentStore : public C2ComponentStore {
 public:
  CuttlefishComponentStore();
  ~CuttlefishComponentStore() override = default;

  void registerCodec(std::shared_ptr<const C2Component::Traits> traits,
                     std::shared_ptr<C2ComponentFactory> factory);

  C2String getName() const override;
  std::vector<std::shared_ptr<const C2Component::Traits>> listComponents()
      override;
  c2_status_t createComponent(
      C2String name, std::shared_ptr<C2Component>* const component) override;
  c2_status_t createInterface(
      C2String name,
      std::shared_ptr<C2ComponentInterface>* const interface) override;
  std::shared_ptr<C2ParamReflector> getParamReflector() const override;
  c2_status_t copyBuffer(std::shared_ptr<C2GraphicBuffer> src,
                         std::shared_ptr<C2GraphicBuffer> dst) override;
  c2_status_t query_sm(
      const std::vector<C2Param*>& stackParams,
      const std::vector<C2Param::Index>& heapParamIndices,
      std::vector<std::unique_ptr<C2Param>>* const heapParams) const override;
  c2_status_t config_sm(
      const std::vector<C2Param*>& params,
      std::vector<std::unique_ptr<C2SettingResult>>* const failures) override;
  c2_status_t querySupportedParams_nb(
      std::vector<std::shared_ptr<C2ParamDescriptor>>* const params)
      const override;
  c2_status_t querySupportedValues_sm(
      std::vector<C2FieldSupportedValuesQuery>& fields) const override;

 private:
  void initCodecs();

  class StoreInterface : public C2InterfaceHelper {
   public:
    explicit StoreInterface(const std::shared_ptr<C2ReflectorHelper>& helper);

    std::shared_ptr<C2StoreIonUsageInfo> mIonUsageInfo;
    std::shared_ptr<C2StoreDmaBufUsageInfo> mDmaBufUsageInfo;
  };

  std::shared_ptr<C2ReflectorHelper> mReflector;
  StoreInterface mInterface;
  std::map<C2String, std::shared_ptr<C2ComponentFactory>> mFactories;
  std::vector<std::shared_ptr<const C2Component::Traits>> mTraits;
};

}  // namespace android
