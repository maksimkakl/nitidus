#include <dlfcn.h>
#include <unistd.h>
#include <string>
#include <pthread.h>
#include "URH.hpp"
#include "main.hpp"
#include "shadowhook.h"
#include "types.hpp"

#define ASYNC_INIT 1

namespace il2cppHook {
  using namespace types;

  static void *il2cppHandle = nullptr;
  static std::vector<void *> hookStubs = {};

  // Исправлено объявление функции под формат pthread
  static void *initURHook(void *arg);

#define DEF_HOOK(N, R, A)         \
  static R(*N##Orig) A = nullptr; \
  static R N##Hook A

#define ADD_HOOK(NAME, ADDR)                                                                                \
  if (ADDR) {                                                                                               \
    auto stub = shadowhook_hook_func_addr(                                                                  \
      reinterpret_cast<void *>(ADDR),                                                                       \
      reinterpret_cast<void *>(NAME##Hook),                                                                 \
      reinterpret_cast<void **>(&NAME##Orig)                                                                \
    );                                                                                                      \
    if (!stub) {                                                                                            \
      int errCode        = shadowhook_get_errno();                                                          \
      const char *errMsg = shadowhook_to_errmsg(errCode);                                                   \
      LOGE("install hook %s failed, errCode: %d, errMsg: %s", #NAME, errCode, errMsg);                      \
    } else {                                                                                                \
      LOGD("hook installed: %s, addr: %lX", #NAME, reinterpret_cast<unsigned long>(ADDR));                  \
      hookStubs.emplace_back(stub);                                                                         \
    }                                                                                                       \
  } else {                                                                                                  \
    LOGE("function address for %s is null, abort adding hook", #NAME);                                      \
  }

#define ADD_HOOK_M(NAME, assemblyName, spaceName, className, methodName, ...)                        \
  auto method##NAME = URH::GetMethod(assemblyName, spaceName, className, methodName, {__VA_ARGS__}); \
  ADD_HOOK(NAME, method##NAME->function)

  // ===================================================================
  // HINT: define hooks here
  // Переименовали хук в getTicket, так как адрес ведет на GetTicket()
  DEF_HOOK(getTicket, void*, (void* self)) {
      void* retval = getTicketOrig(self); // вызов оригинала
  
      if (retval && (uintptr_t)retval > 0x10000000) {
          int32_t length = *(int32_t*)((uintptr_t)retval + 0x10);
          if (length > 0 && length < 5000) {
              char16_t* chars = (char16_t*)((uintptr_t)retval + 0x14);
              std::string ticketStr;
              for (int i = 0; i < length; i++) {
                  if (chars[i] < 0x80) ticketStr += (char)chars[i];
                  else ticketStr += '?';
              }
              LOGD("======================================");
              LOGD("[TICKET] VALUE: %s", ticketStr.c_str());
              LOGD("Длина тикета: %d", length);
              LOGD("======================================");
          }
      } else {
          LOGD("[-] Метод GetTicket вернул null");
      }
  
      return retval;
  }

  // Сама функция теперь возвращает void* для совместимости с pthread
  static void *initURHook(void *arg) {
      LOGD("initURHook запущен, поток: %d. Начинаем поиск libunity.so...", gettid());
  
      uintptr_t base = 0;
      
      // Цикл крутится, пока библиотека не загрузится в память устройства
      while (base == 0) {
          FILE* fp = fopen("/proc/self/maps", "r");
          if (fp) {
              char line[512];
              while (fgets(line, sizeof(line), fp)) {
                  if (strstr(line, "libunity.so")) {
                      sscanf(line, "%lx", &base);
                      break; 
                  }
              }
              fclose(fp);
          }
          
          if (base == 0) {
              LOGD("[*] libunity.so еще не найдена в памяти. Повтор через 3 секунды...");
              sleep(3); // Задержка 3 секунды перед следующим чтением карты памяти
          }
      }
      
      LOGD("[+] libunity.so успешно обнаружена! Base: 0x%lx", base);
  
      // Смещение для GetTicket()
      uintptr_t targetAddr = base + 0x75B4998; 
      ADD_HOOK(getTicket, targetAddr);

      return nullptr;
  }

  void HookIl2cpp(void *handle) {
      il2cppHandle = handle;
      
      // Вместо палевного std::thread создаем скрытный pthread
      pthread_t t;
      pthread_create(&t, nullptr, initURHook, nullptr);
      pthread_detach(t);
  }
}
