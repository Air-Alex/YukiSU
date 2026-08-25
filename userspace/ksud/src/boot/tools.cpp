#include "tools.hpp"
#include "../log.hpp"
#include "../utils.hpp"

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <array>
#include <cerrno>
#include <climits>
#include <cstring>
#include <vector>

namespace ksud {

// Find magiskboot binary: always use current process (multi-call ksud embeds magiskboot).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - keep API for callers
std::string find_magiskboot(const std::string& specified_path, const std::string& workdir) {
    (void)specified_path;
    (void)workdir;
    std::array<char, PATH_MAX> self_path{};
    const ssize_t self_len = readlink("/proc/self/exe", self_path.data(), self_path.size() - 1);
    if (self_len <= 0 || static_cast<size_t>(self_len) >= self_path.size()) {
        LOGE("magiskboot (self): readlink /proc/self/exe failed");
        return "";
    }
    self_path[static_cast<size_t>(self_len)] = '\0';
    if (access(self_path.data(), X_OK) != 0) {
        LOGE("magiskboot (self): not executable: %s", self_path.data());
        return "";
    }
    printf("- Using magiskboot: %s (self)\n", self_path.data());
    return {self_path.data()};
}

// Copy a whole image, replacing the previous `dd` exec. Beyond dropping a PATH
// lookup and a fork+exec of toybox per call, this removes a real hazard: the old
// code retried WITHOUT conv=fsync when the first attempt failed, so a boot
// partition could be left unflushed before a reboot. Here the fsync is not
// optional.
//
// copy_file_range/sendfile are not usable: either endpoint may be a block device
// (a boot partition), which neither supports.
bool exec_dd(const std::string& input, const std::string& output) {
    const int in_fd = open(input.c_str(), O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) {
        LOGE("dd: cannot open %s: %s", input.c_str(), strerror(errno));
        return false;
    }

    // A block-device destination is a partition: never create or truncate it.
    // A regular-file destination is an image we do want to replace outright.
    struct stat dst_st{};
    const bool dst_is_block = stat(output.c_str(), &dst_st) == 0 && S_ISBLK(dst_st.st_mode);
    int out_flags = O_WRONLY | O_CLOEXEC;
    if (!dst_is_block) {
        out_flags |= O_CREAT | O_TRUNC;
    }
    const int out_fd = open(output.c_str(), out_flags, 0600);
    if (out_fd < 0) {
        LOGE("dd: cannot open %s for writing: %s", output.c_str(), strerror(errno));
        close(in_fd);
        return false;
    }

    // Matches the old bs=4M throughput without a 4 MiB buffer.
    constexpr size_t kChunk = 1024UL * 1024;
    std::vector<char> buf(kChunk);
    bool ok = true;
    for (;;) {
        const ssize_t n = read(in_fd, buf.data(), buf.size());
        if (n == 0) {
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOGE("dd: read %s failed: %s", input.c_str(), strerror(errno));
            ok = false;
            break;
        }
        size_t written = 0;
        while (written < static_cast<size_t>(n)) {
            const ssize_t w = write(out_fd, buf.data() + written, static_cast<size_t>(n) - written);
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                LOGE("dd: write %s failed: %s", output.c_str(), strerror(errno));
                ok = false;
                break;
            }
            if (w == 0) {
                // Not reachable for a non-zero count per POSIX, but a driver that
                // does it would spin this loop forever with the partition half
                // written. Fail the flash instead of hanging.
                LOGE("dd: write %s made no progress", output.c_str());
                ok = false;
                break;
            }
            written += static_cast<size_t>(w);
        }
        if (!ok) {
            break;
        }
    }

    // Flush before reporting success: callers may reboot straight after this.
    if (ok && fsync(out_fd) != 0) {
        LOGE("dd: fsync %s failed: %s", output.c_str(), strerror(errno));
        ok = false;
    }
    if (close(out_fd) != 0 && ok) {
        LOGE("dd: close %s failed: %s", output.c_str(), strerror(errno));
        ok = false;
    }
    close(in_fd);
    return ok;
}

// `blockdev --setrw` is a single BLKROSET ioctl. Spawning a process to reach it
// also meant a PATH lookup, and the exit code came back as an opaque number with
// the real errno buried in the child's stderr.
bool set_block_device_rw(const std::string& device) {
    const int fd = open(device.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOGW("setrw: cannot open %s: %s", device.c_str(), strerror(errno));
        return false;
    }
    int read_only = 0;
    const bool ok = ioctl(fd, BLKROSET, &read_only) == 0;
    if (!ok) {
        LOGW("setrw: BLKROSET on %s refused: %s", device.c_str(), strerror(errno));
    }
    close(fd);
    return ok;
}

}  // namespace ksud
