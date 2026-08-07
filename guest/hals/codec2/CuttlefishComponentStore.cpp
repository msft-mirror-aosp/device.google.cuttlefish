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

#define LOG_TAG "CuttlefishComponentStore"

#include "C2CuttlefishHevcDec.h"
#include "CuttlefishComponentStore.h"

#include <C2DmaBufAllocator.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <utils/Log.h>

namespace android {

CuttlefishComponentStore::StoreInterface::StoreInterface(
    const std::shared_ptr<C2ReflectorHelper>& helper)
    : C2InterfaceHelper(helper) {
  setDerivedInstance(this);

  struct Setter {
    static C2R setIonUsage(bool /* mayBlock */, C2P<C2StoreIonUsageInfo>& me) {
      me.set().heapMask = ~0;
      me.set().allocFlags = 0;
      me.set().minAlignment = 0;
      return C2R::Ok();
    };

    static C2R setDmaBufUsage(bool /* mayBlock */,
                              C2P<C2StoreDmaBufUsageInfo>& me) {
      long long usage = (long long)me.get().m.usage;
      if (C2DmaBufAllocator::system_uncached_supported() &&
          !(usage & (C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE))) {
        strncpy(me.set().m.heapName, "system-uncached", me.v.flexCount());
      } else {
        strncpy(me.set().m.heapName, "system", me.v.flexCount());
      }
      me.set().m.allocFlags = 0;
      return C2R::Ok();
    };
  };

  addParameter(
      DefineParam(mIonUsageInfo, "ion-usage")
          .withDefault(new C2StoreIonUsageInfo())
          .withFields(
              {C2F(mIonUsageInfo, usage)
                   .flags({C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE}),
               C2F(mIonUsageInfo, capacity).inRange(0, UINT32_MAX, 1024),
               C2F(mIonUsageInfo, heapMask).any(),
               C2F(mIonUsageInfo, allocFlags).flags({}),
               C2F(mIonUsageInfo, minAlignment).equalTo(0)})
          .withSetter(Setter::setIonUsage)
          .build());

  addParameter(
      DefineParam(mDmaBufUsageInfo, "dmabuf-usage")
          .withDefault(C2StoreDmaBufUsageInfo::AllocShared(0))
          .withFields({
              C2F(mDmaBufUsageInfo, m.usage)
                  .flags({C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE}),
              C2F(mDmaBufUsageInfo, m.capacity).inRange(0, UINT32_MAX, 1024),
              C2F(mDmaBufUsageInfo, m.allocFlags).flags({}),
              C2F(mDmaBufUsageInfo, m.heapName).any(),
          })
          .withSetter(Setter::setDmaBufUsage)
          .build());
}

CuttlefishComponentStore::CuttlefishComponentStore()
    : mReflector(std::make_shared<C2ReflectorHelper>()),
      mInterface(mReflector) {
  initCodecs();
}

void CuttlefishComponentStore::initCodecs() {
  RegisterCuttlefishHevcDec(this, mReflector);
}

void CuttlefishComponentStore::registerCodec(
    std::shared_ptr<const C2Component::Traits> traits,
    std::shared_ptr<C2ComponentFactory> factory) {
  if (traits && factory) {
    mFactories[traits->name] = factory;
    mTraits.push_back(traits);
  }
}

C2String CuttlefishComponentStore::getName() const { return "cuttlefish"; }

std::vector<std::shared_ptr<const C2Component::Traits>>
CuttlefishComponentStore::listComponents() {
  return mTraits;
}

c2_status_t CuttlefishComponentStore::createComponent(
    C2String name, std::shared_ptr<C2Component>* const component) {
  auto it = mFactories.find(name);
  if (it != mFactories.end() && it->second) {
    // TODO: get a unique node ID (similar to C2PlatformComponentStore)
    return it->second->createComponent(0, component,
                                       [](C2Component* p) { delete p; });
  }
  LOG(VERBOSE) << "CuttlefishComponentStore::createComponent not found: "
               << name;
  return C2_NOT_FOUND;
}

c2_status_t CuttlefishComponentStore::createInterface(
    C2String name, std::shared_ptr<C2ComponentInterface>* const interface) {
  auto it = mFactories.find(name);
  if (it != mFactories.end() && it->second) {
    // TODO: get a unique node ID (similar to C2PlatformComponentStore)
    return it->second->createInterface(
        0, interface, [](C2ComponentInterface* p) { delete p; });
  }
  return C2_NOT_FOUND;
}

std::shared_ptr<C2ParamReflector> CuttlefishComponentStore::getParamReflector()
    const {
  return mReflector;
}

c2_status_t CuttlefishComponentStore::copyBuffer(
    std::shared_ptr<C2GraphicBuffer> /*src*/,
    std::shared_ptr<C2GraphicBuffer> /*dst*/) {
  return C2_OMITTED;
}

c2_status_t CuttlefishComponentStore::query_sm(
    const std::vector<C2Param*>& stackParams,
    const std::vector<C2Param::Index>& heapParamIndices,
    std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
  return mInterface.query(stackParams, heapParamIndices, C2_MAY_BLOCK,
                          heapParams);
}

c2_status_t CuttlefishComponentStore::config_sm(
    const std::vector<C2Param*>& params,
    std::vector<std::unique_ptr<C2SettingResult>>* const failures) {
  return mInterface.config(params, C2_MAY_BLOCK, failures);
}

c2_status_t CuttlefishComponentStore::querySupportedParams_nb(
    std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const {
  return mInterface.querySupportedParams(params);
}

c2_status_t CuttlefishComponentStore::querySupportedValues_sm(
    std::vector<C2FieldSupportedValuesQuery>& fields) const {
  return mInterface.querySupportedValues(fields, C2_MAY_BLOCK);
}

}  // namespace android
