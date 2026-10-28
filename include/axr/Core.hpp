// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include <nlohmann/json.hpp>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Stellaria::AXR {
using Json = nlohmann::json;
inline std::filesystem::path Utf8Path(std::string_view text){return std::filesystem::path(std::u8string(text.begin(),text.end()));}
Json ParseBounded(std::string_view encoded);
inline constexpr std::size_t MaximumFrameBytes = 1024*1024;
inline constexpr unsigned ProtocolVersion = 1;
std::string Digest(std::string_view data);
std::string Hmac(std::string_view key, std::string_view data);
bool ConstantEqual(std::string_view a, std::string_view b);
std::string Encrypt(std::string_view key, std::string_view data, std::string_view binding);
std::string Decrypt(std::string_view key, std::string_view data, std::string_view binding);
std::string RandomId();
std::string IntentSeal(const Json& action);
void ValidateAction(const Json& action);
unsigned Risk(const Json& action);
bool ValidTransition(std::string_view from, std::string_view to);
bool Terminal(std::string_view state);
double Now();

class Guard {
public:
    // Public operations on one instance are serialized. This does not combine
    // revalidation and an external application commit into an atomic operation.
    Guard(const std::filesystem::path& path, std::string key, bool migrateLegacy=false);
    ~Guard();
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;
    unsigned Version() const;
    std::string IssueOwner(Json body, double now);
    void RevokeOwner(const std::string& id);
    void RevokeScoped(const std::string& id);
    std::string Check(const Json& action, double now, bool quota=true) const;
    Json Consume(const Json& action, double now);
    Json ExecutionProof(const Json& action, const std::string& consumedId, unsigned version, double now) const;
    void Revalidate(const Json& action, const std::string& id, unsigned version, double now) const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// AXR authenticated durable records.
Json CommitRecord(const Json& previous, const Json& snapshot, std::string_view kind, double now);
bool VerifyRecord(const Json& record, const Json& previous);
bool DurableWrite(const std::filesystem::path& path, std::string_view bytes);

// AXR bounded process primitives.
enum class WorkerProcessState { Stopped, Starting, Running, Canceling, Exited, Crashed, TimedOut };
class WorkerSupervisor {
public:
    WorkerSupervisor();
    ~WorkerSupervisor();
    bool Start(const std::filesystem::path& executable, const std::vector<std::string>& arguments,
               unsigned timeoutMs);
    WorkerProcessState Poll();
    void Stop();
    int ExitCode() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
