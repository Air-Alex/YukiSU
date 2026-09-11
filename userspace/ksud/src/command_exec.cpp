#include "utils.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <array>
#include <cerrno>
#include <cstring>

namespace ksud {
namespace {
class CapturePipe {
public:
    ~CapturePipe() {
        close_end(0);
        close_end(1);
    }
    CapturePipe() = default;
    CapturePipe(const CapturePipe&) = delete;
    CapturePipe& operator=(const CapturePipe&) = delete;
    CapturePipe(CapturePipe&&) = delete;
    CapturePipe& operator=(CapturePipe&&) = delete;
    [[nodiscard]] int fd(int end) const { return fds[end]; }
    void close_end(int end) {
        if (fds[end] >= 0) {
            close(fds[end]);
            fds[end] = -1;
        }
    }
    bool open_pipe() {
        if (pipe2(fds.data(), O_CLOEXEC) != 0)
            return false;
        for (auto& fd : fds) {
            if (fd >= STDERR_FILENO + 1)
                continue;
            const int copy = fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
            if (copy < 0)
                return false;
            close(fd);
            fd = copy;
        }
        return true;
    }

private:
    std::array<int, 2> fds{-1, -1};
};

[[noreturn]] void exec_failed(int fd, int error) {
    const auto* data = reinterpret_cast<const char*>(&error);
    size_t sent = 0;
    while (sent < sizeof(error)) {
        const ssize_t count = write(fd, data + sent, sizeof(error) - sent);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            break;
        sent += static_cast<size_t>(count);
    }
    _exit(127);
}
}  // namespace

ExecResult exec_command(const std::vector<std::string>& args) {
    return exec_command(args, "");
}

ExecResult exec_command(const std::vector<std::string>& args, const std::string& workdir) {
    ExecResult result{-1, "", ""};
    if (args.empty() || args[0].empty()) {
        result.error_number = EINVAL;
        return result;
    }
    for (const auto& arg : args) {
        if (arg.find('\0') != std::string::npos) {
            result.error_number = EINVAL;
            return result;
        }
    }
    if (workdir.find('\0') != std::string::npos) {
        result.error_number = EINVAL;
        return result;
    }
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args)
        argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);

    std::array<CapturePipe, 3> pipes;
    for (auto& pipe : pipes) {
        if (!pipe.open_pipe()) {
            result.error_number = errno;
            return result;
        }
    }
    const pid_t pid = fork();
    if (pid < 0) {
        result.error_number = errno;
        return result;
    }
    if (pid == 0) {
        for (auto& pipe : pipes)
            pipe.close_end(0);
        if (dup2(pipes[0].fd(1), STDOUT_FILENO) < 0 || dup2(pipes[1].fd(1), STDERR_FILENO) < 0)
            exec_failed(pipes[2].fd(1), errno);
        pipes[0].close_end(1);
        pipes[1].close_end(1);
        if (!workdir.empty() && chdir(workdir.c_str()) != 0)
            exec_failed(pipes[2].fd(1), errno);
        execvp(argv[0], argv.data());
        exec_failed(pipes[2].fd(1), errno);
    }

    std::array<pollfd, 3> descriptors{};
    size_t remaining = pipes.size();
    for (size_t i = 0; i < pipes.size(); ++i) {
        pipes[i].close_end(1);
        const int fd = pipes[i].fd(0);
        const int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            result.error_number = errno;
            pipes[i].close_end(0);
            --remaining;
        }
        descriptors[i] = {pipes[i].fd(0), POLLIN, 0};
    }
    std::array<char, 8192> buffer{};
    std::array<char, sizeof(int)> exec_error{};
    size_t error_bytes = 0;
    while (remaining) {
        const int ready = poll(descriptors.data(), descriptors.size(), -1);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            result.error_number = errno;
            break;
        }
        for (size_t i = 0; i < pipes.size(); ++i) {
            if (!descriptors[i].revents || descriptors[i].fd < 0)
                continue;
            for (unsigned batch = 0; batch < 16; ++batch) {
                const ssize_t count = read(descriptors[i].fd, buffer.data(), buffer.size());
                if (count < 0 && errno == EINTR)
                    continue;
                if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    break;
                if (count <= 0) {
                    if (count < 0 && !result.error_number)
                        result.error_number = errno;
                    pipes[i].close_end(0);
                    descriptors[i].fd = -1;
                    --remaining;
                    break;
                }
                const auto size = static_cast<size_t>(count);
                if (i == 0)
                    result.stdout_str.append(buffer.data(), size);
                else if (i == 1)
                    result.stderr_str.append(buffer.data(), size);
                else if (size <= exec_error.size() - error_bytes) {
                    memcpy(exec_error.data() + error_bytes, buffer.data(), size);
                    error_bytes += size;
                } else
                    result.error_number = EIO;
            }
        }
    }
    for (auto& pipe : pipes)
        pipe.close_end(0);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0)
        result.error_number = errno;
    else if (WIFEXITED(status))
        result.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        result.exit_code = 128 + WTERMSIG(status);
    if (error_bytes == sizeof(int))
        memcpy(&result.error_number, exec_error.data(), sizeof(int));
    else if (error_bytes)
        result.error_number = EIO;
    if (result.error_number && result.stderr_str.empty())
        result.stderr_str = args[0] + ": " + std::strerror(result.error_number) + "\n";
    if (result.error_number && result.exit_code == 0)
        result.exit_code = -1;
    return result;
}
}  // namespace ksud
