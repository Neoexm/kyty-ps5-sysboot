#ifndef KYTY_PS5_KERNEL_IPMI_SCOPE_H_
#define KYTY_PS5_KERNEL_IPMI_SCOPE_H_

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace Libs::LibKernel::IpmiScope {

// Host-local service directory shared by the scope's processes. All calls fail when disabled.
bool Enabled();
bool Register(const std::string& service, uint32_t guest_pid, uint32_t* assigned_id,
              bool* duplicate = nullptr);
bool Lookup(const std::string& service, uint32_t* service_id, uint32_t* owner_guest_pid,
            uint32_t* owner_host_pid);
// A client handle lives only as long as its server and owner process.
bool OpenClient(const std::string& service, uint32_t guest_pid, uint32_t* client_id,
                uint32_t* server_id, uint32_t event_count = 1, uint32_t queue_count = 0,
                const uint64_t* queue_capacities = nullptr);
enum class ClientStatus { Unavailable, Missing, Live };
ClientStatus QueryClient(uint32_t client_id, uint32_t* server_id, uint32_t* owner_guest_pid);
bool         InspectClient(uint32_t client_id, uint32_t* server_id, uint32_t* owner_guest_pid);
bool         InspectPeerClient(uint32_t server_id, uint32_t client_id, uint32_t* guest_pid,
                               uint32_t* host_pid = nullptr, uint64_t* host_creation_time = nullptr,
                               bool reap_exited = true);
bool         Unregister(uint32_t server_id);
bool         CloseClient(uint32_t client_id);
// Like the kernel's per-conn 16-slot ticket table: 0x241 stamps, 0x444 is bookkeeping, 0x242 posts
// and raises the event, 0x243 fetches by ticket. stamped inside QueueRequest so a fast server can't
// post 0x242 first
struct AsyncIssue {
	uint32_t event_index;
	uint32_t ticket;
	uint64_t pattern;
};
bool QueueRequest(uint32_t client_id, const uint8_t* bytes, size_t length, uint32_t* request_id,
                  const AsyncIssue* async = nullptr, bool* table_full = nullptr);
bool PostAsyncResult(uint32_t server_id, uint32_t client_id, uint32_t ticket, uint32_t selector,
                     uint32_t result, uint32_t out_count, const uint8_t* msg, size_t msg_size,
                     uint32_t* event_index, uint64_t* event_pattern);
enum class AsyncFetchStatus { Got, Empty, Mismatch, Missing, Unavailable };
AsyncFetchStatus FetchAsyncResult(uint32_t client_id, uint32_t selector, uint32_t ticket,
                                  uint32_t out_count, const uint64_t* caps, uint32_t* result,
                                  std::vector<uint8_t>* payload);
// owner posts to its own server queue; client_id 0, no reply
bool QueueServerEvent(uint32_t server_id, uint32_t type, uint32_t* request_id,
                      bool* missing = nullptr);
bool TryReceive(uint32_t server_id, uint32_t* request_id, uint32_t* client_id,
                std::vector<uint8_t>* bytes);
bool Reply(uint32_t server_id, uint32_t request_id, const uint8_t* bytes, size_t length);
bool TryReadReply(uint32_t client_id, uint32_t request_id, std::vector<uint8_t>* bytes);
bool CancelRequest(uint32_t client_id, uint32_t request_id);
bool RequeueRequest(uint32_t server_id, uint32_t request_id);
bool IsReceivedRequest(uint32_t server_id, uint32_t client_id, uint32_t request_id);
// Server->client queues (0x253/0x254 send, 0x251/0x252 get, 0x255 flush), one channel per index
enum class MessageStatus { Queued, Full, Missing, Unavailable, Invalid, OverCapacity };
enum class FetchStatus { Got, TooBig, Empty, Missing, Unavailable };
MessageStatus QueueUserMessage(uint32_t server_id, uint32_t client_id, uint32_t index,
                               const uint8_t* bytes, size_t length);
FetchStatus   ReadUserMessage(uint32_t client_id, uint32_t index, size_t capacity,
                              std::vector<uint8_t>* bytes);
bool          FlushUserMessages(uint32_t server_id, uint32_t client_id, uint32_t index);
enum class EventStatus { Matched, Pending, InvalidIndex, Missing, Unavailable };
EventStatus PollClientEvent(uint32_t client_id, uint32_t index, uint64_t desired, uint32_t mode,
                            uint32_t generation, uint64_t* current);
EventStatus SetClientEvent(uint32_t server_id, uint32_t client_id, uint32_t index, uint64_t bits);
EventStatus ResetClientEvents(uint32_t client_id, uint32_t event_count, uint32_t* generation);
EventStatus CancelClientEvents(uint32_t client_id);
bool        WaitClientEventHint(uint32_t client_id, uint32_t milliseconds);
} // namespace Libs::LibKernel::IpmiScope

#endif
