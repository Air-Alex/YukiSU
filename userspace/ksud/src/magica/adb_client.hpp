#pragma once

#include <cstdint>
#include <string>

namespace ksud::magica {

class AdbClient {
public:
    AdbClient();
    ~AdbClient();

    AdbClient(const AdbClient&) = delete;
    AdbClient& operator=(const AdbClient&) = delete;

    bool connect_tcp(const std::string& host, uint16_t port);
    bool shell_command(const std::string& command, std::string* output);

    [[nodiscard]] const std::string& last_error() const;

private:
    int sockfd_;
    uint32_t local_id_;
    uint32_t remote_id_;
    uint32_t max_payload_;
    std::string last_error_;
    std::string pending_output_;

    bool send_connect();
    bool open_shell(const std::string& command);
    bool send_packet(uint32_t command, uint32_t arg0, uint32_t arg1, const std::string& payload);
    bool read_packet(uint32_t* command, uint32_t* arg0, uint32_t* arg1, std::string* payload);
    void close_socket();
    void set_error(std::string message);
};

}  // namespace ksud::magica
