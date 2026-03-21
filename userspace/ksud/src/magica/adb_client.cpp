#include "adb_client.hpp"

#include "../log.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <string_view>

namespace ksud::magica {

namespace {

constexpr uint32_t A_SYNC = 0x434e5953;
constexpr uint32_t A_CNXN = 0x4e584e43;
constexpr uint32_t A_OPEN = 0x4e45504f;
constexpr uint32_t A_OKAY = 0x59414b4f;
constexpr uint32_t A_CLSE = 0x45534c43;
constexpr uint32_t A_WRTE = 0x45545257;
constexpr uint32_t A_AUTH = 0x48545541;

constexpr uint32_t kAdbVersion = 0x01000001;
constexpr uint32_t kMaxPayload = 4096;
constexpr int kIoTimeoutMs = 30000;

struct AdbMessage {
    uint32_t command;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t data_length;
    uint32_t data_check;
    uint32_t magic;
};

uint32_t adb_checksum(const std::string& payload) {
    uint32_t sum = 0;
    for (const unsigned char ch : payload) {
        sum += ch;
    }
    return sum;
}

const char* adb_command_name(uint32_t command) {
    switch (command) {
    case A_SYNC:
        return "SYNC";
    case A_CNXN:
        return "CNXN";
    case A_OPEN:
        return "OPEN";
    case A_OKAY:
        return "OKAY";
    case A_CLSE:
        return "CLSE";
    case A_WRTE:
        return "WRTE";
    case A_AUTH:
        return "AUTH";
    default:
        return "UNKN";
    }
}

std::string payload_preview(std::string_view payload) {
    constexpr size_t kPreviewLimit = 80;

    std::ostringstream oss;
    const size_t preview_size = std::min(payload.size(), kPreviewLimit);
    for (size_t i = 0; i < preview_size; ++i) {
        const unsigned char ch = static_cast<unsigned char>(payload[i]);
        switch (ch) {
        case '\0':
            oss << "\\0";
            break;
        case '\n':
            oss << "\\n";
            break;
        case '\r':
            oss << "\\r";
            break;
        case '\t':
            oss << "\\t";
            break;
        default:
            if (std::isprint(ch) != 0) {
                oss << static_cast<char>(ch);
            } else {
                oss << "\\x";
                constexpr char kHex[] = "0123456789abcdef";
                oss << kHex[(ch >> 4U) & 0x0fU] << kHex[ch & 0x0fU];
            }
            break;
        }
    }

    if (payload.size() > preview_size) {
        oss << "...";
    }
    return oss.str();
}

void log_packet(const char* direction, uint32_t command, uint32_t arg0, uint32_t arg1,
                std::string_view payload) {
    LOGI("ADB %s %s arg0=%u arg1=%u len=%zu payload='%s'", direction, adb_command_name(command),
         arg0, arg1, payload.size(), payload_preview(payload).c_str());
}

bool wait_for_fd(int fd, short events, int timeout_ms) {
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = events;
    pfd.revents = 0;

    while (true) {
        const int ret = poll(&pfd, 1, timeout_ms);
        if (ret > 0) {
            return (pfd.revents & events) != 0;
        }
        if (ret == 0) {
            return false;
        }
        if (errno != EINTR) {
            return false;
        }
    }
}

bool write_all(int fd, const void* data, size_t size) {
    const auto* ptr = static_cast<const uint8_t*>(data);
    size_t written = 0;
    while (written < size) {
        if (!wait_for_fd(fd, POLLOUT, kIoTimeoutMs)) {
            return false;
        }
        const ssize_t ret = send(fd, ptr + written, size - written, MSG_NOSIGNAL);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (ret == 0) {
            return false;
        }
        written += static_cast<size_t>(ret);
    }
    return true;
}

bool read_all(int fd, void* data, size_t size) {
    auto* ptr = static_cast<uint8_t*>(data);
    size_t read_size = 0;
    while (read_size < size) {
        if (!wait_for_fd(fd, POLLIN, kIoTimeoutMs)) {
            return false;
        }
        const ssize_t ret = recv(fd, ptr + read_size, size - read_size, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (ret == 0) {
            return false;
        }
        read_size += static_cast<size_t>(ret);
    }
    return true;
}

}  // namespace

AdbClient::AdbClient() : sockfd_(-1), local_id_(1), remote_id_(0), max_payload_(kMaxPayload) {}

AdbClient::~AdbClient() {
    close_socket();
}

bool AdbClient::connect_tcp(const std::string& host, uint16_t port) {
    close_socket();
    pending_output_.clear();
    max_payload_ = kMaxPayload;

    sockfd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sockfd_ < 0) {
        set_error(std::string("socket failed: ") + strerror(errno));
        return false;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        set_error("invalid ADB host address: " + host);
        close_socket();
        return false;
    }

    if (connect(sockfd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        set_error(std::string("connect failed: ") + strerror(errno));
        close_socket();
        return false;
    }

    LOGI("ADB TCP connected to %s:%u", host.c_str(), port);

    if (!send_connect()) {
        close_socket();
        return false;
    }

    return true;
}

bool AdbClient::shell_command(const std::string& command, std::string* output) {
    if (sockfd_ < 0) {
        set_error("ADB socket is not connected");
        return false;
    }

    remote_id_ = 0;
    if (output) {
        output->clear();
    }
    pending_output_.clear();

    if (!open_shell(command)) {
        return false;
    }

    if (output && !pending_output_.empty()) {
        output->append(pending_output_);
        pending_output_.clear();
    }

    while (true) {
        uint32_t packet_cmd = 0;
        uint32_t arg0 = 0;
        uint32_t arg1 = 0;
        std::string payload;
        if (!read_packet(&packet_cmd, &arg0, &arg1, &payload)) {
            return false;
        }

        if (packet_cmd == A_OKAY) {
            if (arg1 == local_id_) {
                remote_id_ = arg0;
            }
            continue;
        }

        if (packet_cmd == A_WRTE) {
            if (arg1 != local_id_) {
                continue;
            }
            if (remote_id_ == 0) {
                remote_id_ = arg0;
            }
            if (output) {
                output->append(payload);
            }
            if (!send_packet(A_OKAY, local_id_, remote_id_, "")) {
                return false;
            }
            continue;
        }

        if (packet_cmd == A_CLSE) {
            if (arg1 != local_id_) {
                continue;
            }
            return true;
        }

        if (packet_cmd == A_AUTH) {
            set_error("secure ADB authentication is not supported by the native Magica client");
            return false;
        }

        if (packet_cmd == A_SYNC) {
            continue;
        }

        set_error("unexpected ADB packet during shell session");
        return false;
    }
}

const std::string& AdbClient::last_error() const {
    return last_error_;
}

bool AdbClient::send_connect() {
    const std::string banner = "host::yukisu-magica";
    if (!send_packet(A_CNXN, kAdbVersion, kMaxPayload, banner)) {
        return false;
    }

    while (true) {
        uint32_t packet_cmd = 0;
        uint32_t arg0 = 0;
        uint32_t arg1 = 0;
        std::string payload;
        if (!read_packet(&packet_cmd, &arg0, &arg1, &payload)) {
            return false;
        }

        if (packet_cmd == A_CNXN) {
            max_payload_ = arg1 == 0 ? kMaxPayload : arg1;
            LOGI("ADB connected: version=0x%x maxdata=%u banner=%s", arg0, max_payload_,
                 payload.c_str());
            return true;
        }

        if (packet_cmd == A_AUTH) {
            set_error("adbd still requires authentication after enabling ro.adb.secure=0");
            return false;
        }

        if (packet_cmd == A_SYNC) {
            continue;
        }

        set_error("unexpected ADB packet during connect");
        return false;
    }
}

bool AdbClient::open_shell(const std::string& command) {
    std::string service = "shell:" + command;
    service.push_back('\0');
    if (!send_packet(A_OPEN, local_id_, 0, service)) {
        return false;
    }

    while (true) {
        uint32_t packet_cmd = 0;
        uint32_t arg0 = 0;
        uint32_t arg1 = 0;
        std::string payload;
        if (!read_packet(&packet_cmd, &arg0, &arg1, &payload)) {
            return false;
        }

        if (packet_cmd == A_OKAY && arg1 == local_id_) {
            remote_id_ = arg0;
            LOGI("ADB shell stream opened: local_id=%u remote_id=%u", local_id_, remote_id_);
            return true;
        }

        if (packet_cmd == A_WRTE && arg1 == local_id_) {
            if (remote_id_ == 0) {
                remote_id_ = arg0;
            }
            pending_output_.append(payload);
            if (!send_packet(A_OKAY, local_id_, remote_id_, "")) {
                return false;
            }
            continue;
        }

        if (packet_cmd == A_CLSE && arg1 == local_id_) {
            set_error("adbd closed the shell stream immediately");
            return false;
        }

        if (packet_cmd == A_AUTH) {
            set_error("secure ADB authentication is not supported by the native Magica client");
            return false;
        }

        if (packet_cmd == A_SYNC) {
            continue;
        }

        set_error("unexpected ADB packet while opening shell stream");
        return false;
    }
}

bool AdbClient::send_packet(uint32_t command, uint32_t arg0, uint32_t arg1,
                            const std::string& payload) {
    if (sockfd_ < 0) {
        set_error("ADB socket is not connected");
        return false;
    }

    AdbMessage msg{};
    msg.command = command;
    msg.arg0 = arg0;
    msg.arg1 = arg1;
    msg.data_length = static_cast<uint32_t>(payload.size());
    msg.data_check = adb_checksum(payload);
    msg.magic = command ^ 0xffffffffU;

    log_packet("SEND", command, arg0, arg1, payload);

    if (!write_all(sockfd_, &msg, sizeof(msg))) {
        set_error(std::string("failed to write ADB header: ") + strerror(errno));
        return false;
    }

    if (!payload.empty() && !write_all(sockfd_, payload.data(), payload.size())) {
        set_error(std::string("failed to write ADB payload: ") + strerror(errno));
        return false;
    }

    return true;
}

bool AdbClient::read_packet(uint32_t* command, uint32_t* arg0, uint32_t* arg1,
                            std::string* payload) {
    if (sockfd_ < 0) {
        set_error("ADB socket is not connected");
        return false;
    }

    AdbMessage msg{};
    if (!read_all(sockfd_, &msg, sizeof(msg))) {
        set_error(std::string("failed to read ADB header: ") + strerror(errno));
        return false;
    }

    if (msg.magic != (msg.command ^ 0xffffffffU)) {
        set_error("ADB packet magic mismatch");
        return false;
    }

    if (msg.data_length > kMaxPayload * 16U) {
        set_error("ADB payload is unexpectedly large");
        return false;
    }

    std::string buffer;
    if (msg.data_length != 0U) {
        buffer.resize(msg.data_length);
        if (!read_all(sockfd_, buffer.data(), msg.data_length)) {
            set_error(std::string("failed to read ADB payload: ") + strerror(errno));
            return false;
        }

        if (msg.command != A_CNXN && msg.command != A_AUTH &&
            adb_checksum(buffer) != msg.data_check) {
            set_error("ADB payload checksum mismatch");
            return false;
        }
    }

    if (command) {
        *command = msg.command;
    }
    if (arg0) {
        *arg0 = msg.arg0;
    }
    if (arg1) {
        *arg1 = msg.arg1;
    }
    if (payload) {
        *payload = std::move(buffer);
    }

    log_packet("RECV", msg.command, msg.arg0, msg.arg1, payload ? *payload : std::string_view{});

    return true;
}

void AdbClient::close_socket() {
    if (sockfd_ >= 0) {
        close(sockfd_);
        sockfd_ = -1;
    }
    remote_id_ = 0;
    pending_output_.clear();
}

void AdbClient::set_error(std::string message) {
    last_error_ = std::move(message);
    LOGE("%s", last_error_.c_str());
}

}  // namespace ksud::magica
