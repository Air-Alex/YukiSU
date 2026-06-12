#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ksud::sucompat {

inline constexpr const char* kSuSocketName = "ksu_su_broker";

inline constexpr uint32_t kSuMagic = 0x4B535553U;  // "KSUS"

inline constexpr uint32_t kSuMaxPayload = 256U * 1024U;

// Followed by payload_len bytes: cwd\0arg0\0...\0env(envc-1)\0
struct __attribute__((packed)) SuRequest {
    uint32_t magic;
    uint32_t argc;
    uint32_t envc;
    uint32_t payload_len;
};

struct __attribute__((packed)) SuResult {
    uint32_t magic;
    int32_t granted;
    int32_t exit_code;
};

std::string build_payload(const std::string& cwd, int argc, char** argv, char** envp,
                          uint32_t* out_argc, uint32_t* out_envc);

bool parse_payload(const std::string& buf, uint32_t argc, uint32_t envc, std::string* cwd,
                   std::vector<std::string>* args, std::vector<std::string>* env);

bool write_all(int fd, const void* buf, size_t len);
bool read_all(int fd, void* buf, size_t len);

bool send_with_fds(int sock, const void* buf, size_t len, const int* fds, int nfds);

bool recv_with_fds(int sock, void* buf, size_t len, int* out_fds, int max_fds, int* out_nfds);

}  // namespace ksud::sucompat
