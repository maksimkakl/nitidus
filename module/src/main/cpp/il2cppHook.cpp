#include <dlfcn.h>
#include <unistd.h>
#include <string>
#include <thread>
#include "URH.hpp"
#include "main.hpp"
#include "shadowhook.h"
#include "types.hpp"

#define ASYNC_INIT 1

namespace il2cppHook {
  using namespace types;

  static void *il2cppHandle = nullptr;
  static std::thread initThread;
  static std::vector<void *> hookStubs = {};

  static void initURHook();

#define DEF_HOOK(N, R, A)         \
  static R(*N##Orig) A = nullptr; \
  static R N##Hook A

#define ADD_HOOK(NAME, ADDR)                                                               \
  if (ADDR) {                                                                              \
    auto stub = shadowhook_hook_func_addr(                                                 \
      reinterpret_cast<void *>(ADDR),                                                      \
      reinterpret_cast<void *>(NAME##Hook),                                                \
      reinterpret_cast<void **>(&NAME##Orig)                                               \
    );                                                                                     \
    if (!stub) {                                                                           \
      int errCode        = shadowhook_get_errno();                                         \
      const char *errMsg = shadowhook_to_errmsg(errCode);                                  \
      LOGE("install hook %s failed, errCode: %d, errMsg: %s", #NAME, errCode, errMsg);     \
    } else {                                                                               \
      LOGD("hook installed: %s, addr: %lX", #NAME, reinterpret_cast<unsigned long>(ADDR)); \
      hookStubs.emplace_back(stub);                                                        \
    }                                                                                      \
  } else {                                                                                 \
    LOGE("function address for %s is null, abort adding hook", #NAME);                     \
  }

#define ADD_HOOK_M(NAME, assemblyName, spaceName, className, methodName, ...)                        \
  auto method##NAME = URH::GetMethod(assemblyName, spaceName, className, methodName, {__VA_ARGS__}); \
  ADD_HOOK(NAME, method##NAME->function)

  // ===================================================================
  // HINT: define hooks here

  static void initURHook() {
      LOGD("initURHook tid: %d", gettid());
  
      uintptr_t base = 0;
      FILE* fp = fopen("/proc/self/maps", "r");
      if (fp) {
          char line[512];
          while (fgets(line, sizeof(line), fp)) {
              if (strstr(line, "libunity.so")) {
                  sscanf(line, "%" PRIxPTR, &base);
                  break;
              }
          }
          fclose(fp);
      }
      LOGD("libunity.so base: 0x%" PRIxPTR, base);
  
      uintptr_t targetAddr = base + 0x75B4998; // начало функции как во Frida
      ADD_HOOK(getToken, targetAddr)
  }
  
  // Аналог onLeave во Frida — вызываем оригинал, читаем результат
  DEF_HOOK(getToken, void*, (void* self)) {
      void* retval = getTokenOrig(self); // вызов оригинала
  
      // Аналог onLeave retval
      if (retval && (uintptr_t)retval > 0x10000000) {
          int32_t length = *(int32_t*)((uintptr_t)retval + 0x10);
          if (length > 0 && length < 5000) {
              char16_t* chars = (char16_t*)((uintptr_t)retval + 0x14);
              std::string token;
              for (int i = 0; i < length; i++) {
                  if (chars[i] < 0x80) token += (char)chars[i];
                  else token += '?';
              }
              LOGD("======================================");
              LOGD("[TOKEN] VALUE: %s", token.c_str());
              LOGD("Длина: %d", length);
              LOGD("======================================");
          }
      } else {
          LOGD("[-] Метод вернул null");
      }
  
      return retval; // обязательно возвращаем!
  }

  void HookIl2cpp(void *handle) {
      il2cppHandle = handle;
      // il2cpp_init нет в libunity.so, запускаем напрямую
      initThread = std::thread(initURHook);
  }
}
