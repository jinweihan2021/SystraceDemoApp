#include <jni.h>
#include <string>

#include <atomic>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <unordered_set>
#include <android/log.h>
#include <fcntl.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <chrono>
#include <sys/prctl.h>

#include <stdlib.h>
#include <libgen.h>
#include <sys/system_properties.h>
#include <vector>
#include <array>
#include <syscall.h>
#include "build.h"
#include "linker.h"
#include "hooks.h"
#include "plthooks.h"
#include "log.h"

#define  LOG_TAG    "HOOOOOOOOK"
#define  ALOG(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
static const int64_t kSecondNanos = 1000000000;
int const kTracerMagicFd = -100;

constexpr auto kSingleLibMinSdk = 27;
constexpr auto kLibWhitelistMinSdk = 23;
constexpr char kSingleLibName[] = "libcutils.so";

constexpr char kAtraceSymbol[] = "atrace_setup";
constexpr char kSysLibPrefix[] = "/system";

int *atrace_marker_fd = nullptr;
std::atomic<uint64_t> *atrace_enabled_tags = nullptr;
std::atomic<uint64_t> original_tags(UINT64_MAX);
std::atomic<bool> systrace_installed;
bool first_enable = true;

std::ofstream *os = nullptr;

std::mutex mtx_;

int32_t threadID() {
    return static_cast<int32_t>(syscall(__NR_gettid));
}

std::string threadName() {
    constexpr int kMaxThreadNameSize = 100;
    char threadName[kMaxThreadNameSize];
    if (prctl(PR_GET_NAME, threadName) != 0) {
        return "";
    } else {
        return threadName;
    }
}

void log_systrace(const void *buf, size_t count) {
    const char *msg = reinterpret_cast<const char *>(buf);

    if (os != nullptr && os->is_open()) {
        std::lock_guard<std::mutex> lockC(mtx_);

        char buffer[1024];
        auto start = std::chrono::steady_clock::now().time_since_epoch();
        auto sec =
                std::chrono::duration_cast<std::chrono::microseconds>(start).count() / 1000000.0f;
        int n = sprintf(buffer, "<%s>-%d (-----) [001] .... %.5f: tracing_mark_write: %s\n",
                        threadName().c_str(), threadID(), sec, msg);
        os->write(buffer, n);

        ALOG("%s", buffer);
    }
}

bool should_log_systrace(int fd, size_t count) {
    return systrace_installed && fd == *atrace_marker_fd && count > 0;
}

ssize_t write_hook(int fd, const void *buf, size_t count) {
    if (should_log_systrace(fd, count)) {
        log_systrace(buf, count);
        return count;
    }
    return CALL_PREV(write_hook, fd, buf, count);
}

ssize_t __write_chk_hook(int fd, const void *buf, size_t count, size_t buf_size) {
    if (should_log_systrace(fd, count)) {
        log_systrace(buf, count);
        return count;
    }
    return CALL_PREV(__write_chk_hook, fd, buf, count, buf_size);
}

plt_hook_spec &getSingleLibFunctionSpec() {
    static plt_hook_spec spec{
            "__write_chk", reinterpret_cast<void *>(__write_chk_hook)};
    return spec;
}

constexpr auto kWhitelistSize = 7;

std::array<std::string, kWhitelistSize> &getLibWhitelist() {
    static std::array<std::string, kWhitelistSize> whitelist = {
            {"libandroid_runtime.so",
                    "libui.so",
                    "libgui.so",
                    "libart.so",
                    "libhwui.so",
                    "libEGL.so",
                    "libcutils.so"}};
    return whitelist;
}

std::vector<plt_hook_spec> &getFunctionHooks() {
    static std::vector<plt_hook_spec> functionHooks = {
            {"libc.so", "write",       reinterpret_cast<void *>(&write_hook)},
            {"libc.so", "__write_chk", reinterpret_cast<void *>(__write_chk_hook)},
    };
    return functionHooks;
}

// Returns the set of libraries that we don't want to hook.
std::unordered_set<std::string> &getSeenLibs() {
    static std::unordered_set<std::string> seenLibs;

    // Add this library's name to the set that we won't hook
    if (seenLibs.size() == 0) {
        seenLibs.insert("libc.so");

        Dl_info info;
        if (!dladdr((void *) &getSeenLibs, &info)) {
            LOGE("Failed to find module name");
        }
        if (info.dli_fname == nullptr) {
            // Not safe to continue as a thread may block trying to hook the current
            // library
            throw std::runtime_error("could not resolve current library");
        }

        seenLibs.insert(basename(info.dli_fname));
    }
    return seenLibs;
}

// Determine if this library should be hooked.
bool allowHookingCb(char const *libname, char const *full_libname, void *data) {
    std::unordered_set<std::string> *seenLibs =
            static_cast<std::unordered_set<std::string> *>(data);

    if (seenLibs->find(libname) != seenLibs->cend()) {
        // We already hooked (or saw and decided not to hook) this library.
        return false;
    }

    seenLibs->insert(libname);

    // Only allow to hook system libraries
    if (strncmp(full_libname, kSysLibPrefix, sizeof(kSysLibPrefix) - 1)) {
        return false;
    }

    // Verify if the library contains atrace indicator symbol, otherwise we
    // don't need to install hooks.
    auto result = facebook::linker::sharedLib(libname);
    if (!result.success) {
        return false;
    }
    ElfW(Sym) const *sym = result.data.find_symbol_by_name(kAtraceSymbol);
    if (!sym) {
        return false;
    }

    return true;
}

/**
* plt hook libc 的 write 方法
*/
void hookLoadedLibs() {
    auto sdk = facebook::build::getAndroidSdk();
    if (sdk >= kSingleLibMinSdk) {
        auto &spec = getSingleLibFunctionSpec();
        hook_single_lib(kSingleLibName, &spec, 1);
        return;
    }

    if (sdk >= kLibWhitelistMinSdk) {
        auto &whitelist = getLibWhitelist();
        auto &functionSpecs = getFunctionHooks();
        for (auto &lib : whitelist) {
            auto failures = hook_single_lib(
                    lib.c_str(), functionSpecs.data(), functionSpecs.size());
            if (failures) {
                throw std::runtime_error("Hook failed for library: " + lib);
            }
        }
        return;
    }

    auto &functionHooks = getFunctionHooks();
    auto &seenLibs = getSeenLibs();

    facebook::plthooks::hooks::hookLoadedLibs(
            functionHooks, allowHookingCb, &seenLibs);
}

void installSystraceSnooper() {
    auto sdk = facebook::build::getAndroidSdk();
    {
        std::string lib_name("libcutils.so");
        std::string enabled_tags_sym("atrace_enabled_tags");
        std::string fd_sym("atrace_marker_fd");

        if (sdk < 18) {
            lib_name = "libutils.so";
            // android::Tracer::sEnabledTags
            enabled_tags_sym = "_ZN7android6Tracer12sEnabledTagsE";
            // android::Tracer::sTraceFD
            fd_sym = "_ZN7android6Tracer8sTraceFDE";
        }

        void *handle;
        if (sdk < 21) {
            handle = dlopen(lib_name.c_str(), RTLD_LOCAL);
        } else {
            handle = dlopen(nullptr, RTLD_GLOBAL);
        }

        atrace_enabled_tags =
                reinterpret_cast<std::atomic<uint64_t> *>(
                        dlsym(handle, enabled_tags_sym.c_str()));

        if (atrace_enabled_tags == nullptr) {
            throw std::runtime_error("Enabled Tags not defined");
        }

        atrace_marker_fd =
                reinterpret_cast<int *>(dlsym(handle, fd_sym.c_str()));

        if (atrace_marker_fd == nullptr) {
            throw std::runtime_error("Trace FD not defined");
        }
        if (*atrace_marker_fd == -1) {
            // This is a case that can happen for older Android version i.e. 4.4
            // in which scenario the marker fd is not initialized/opened  by Zygote.
            // Nevertheless for Profilo trace it is not necessary to have an open fd,
            // since all we really need is to ensure that we 'know' it is marker
            // fd to continue writing Profilo logs, thus the usage of marker fd
            // acting really as a placeholder for magic id.
            *atrace_marker_fd = kTracerMagicFd;
        }
    }

    ALOG("atrace_enabled_tags=%x", atrace_enabled_tags);
    ALOG("atrace_marker_fd=%x", atrace_marker_fd);

    if (plthooks_initialize()) {
        throw std::runtime_error("Could not initialize plthooks library");
    }

    hookLoadedLibs();

    systrace_installed = true;
}

void enableSystrace(std::string const &trace_file) {
    if (!systrace_installed) {
        return;
    }

    if (!first_enable) {
        // On every enable, except the first one, find if new libs were loaded
        // and install systrace hook for them
        try {
            hookLoadedLibs();
        } catch (...) {
            // It's ok to continue if the refresh has failed
        }
    }
    first_enable = false;

    auto prev = atrace_enabled_tags->exchange(UINT64_MAX);
    if (prev !=
        UINT64_MAX) { // if we somehow call this twice in a row, don't overwrite the real tags
        original_tags = prev;
    }

    if (os != nullptr && os->is_open()) {
        os->close();
    }

    os = new std::ofstream();
    os->open(trace_file, std::ios::out | std::ios::trunc);
    os->write("TRACE:\n", 7);
    os->write("# tracer: nop\n", 13);
    ALOG("trace_file_name=%s", trace_file.c_str());
}

void restoreSystrace() {
    if (!systrace_installed) {
        return;
    }

    uint64_t tags = original_tags;
    if (tags != UINT64_MAX) { // if we somehow call this before enableSystrace, don't screw it up
        atrace_enabled_tags->store(tags);
    }

    if (os != nullptr) {
        os->close();
        os = nullptr;
    }
}

bool installSystraceHook() {
    try {
        installSystraceSnooper();
        return true;
    } catch (const std::runtime_error &e) {
        LOGW("could not install hooks: %s", e.what());
        return false;
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_linkedin_android_atrace_Atrace_enableSystraceNative(JNIEnv *env, jclass type,
                                                             jstring filepath) {
    const char *cstr = env->GetStringUTFChars(filepath, nullptr);
    std::string str = std::string(cstr);
    enableSystrace(str);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_linkedin_android_atrace_Atrace_restoreSystraceNative(JNIEnv *env, jclass type) {
    restoreSystrace();
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_linkedin_android_atrace_Atrace_installSystraceHook(JNIEnv *env, jclass type) {
    return static_cast<jboolean>(installSystraceHook());
}
