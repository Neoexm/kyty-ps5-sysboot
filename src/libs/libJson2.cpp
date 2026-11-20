#include "common/abi.h"
#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "kernel/fileSystem.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <atomic>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_set>
#include <vector>

namespace Libs {

namespace LibJson2 {

LIB_VERSION("Json2", 1, "Json2", 1, 1);

enum JsonValueType : uint32_t {
	JsonValueTypeNull = 0,
	JsonValueTypeBoolean,
	JsonValueTypeInteger,
	JsonValueTypeUInteger,
	JsonValueTypeReal,
	JsonValueTypeString,
	JsonValueTypeArray,
	JsonValueTypeObject,
};

constexpr int32_t JSON_ERROR_PARSE_INVALID_CHAR = -2138799871; // 0x80848101
constexpr int32_t JSON_ERROR_NOMEM              = -2138799870; // 0x80848102
constexpr int32_t JSON_ERROR_NOFILE             = -2138799869; // 0x80848103
constexpr int32_t JSON_ERROR_NOROOT             = -2138799868; // 0x80848104
constexpr int32_t JSON_ERROR_NOBUF              = -2138799867; // 0x80848105
constexpr int32_t JSON_ERROR_NOINIT             = -2138799856; // 0x80848110
constexpr int32_t JSON_ERROR_MULTIPLEINIT       = -2138799855; // 0x80848111
constexpr int32_t JSON_ERROR_ALREADY_SET        = -2138799854; // 0x80848112
constexpr int32_t JSON_ERROR_NOT_SUPPORTED      = -2138799853; // 0x80848113
constexpr int32_t JSON_ERROR_SPECIAL_FLOAT      = -2138799852; // 0x80848114
constexpr int32_t JSON_ERROR_INVALID_ARGUMENT   = -2138799840; // 0x80848120

static std::atomic<uint32_t> g_json_noinit_trace {0};
static std::atomic<uint32_t> g_json_parse_trace {0};
static std::atomic<uint32_t> g_json_lookup_trace {0};
static std::atomic<uint32_t> g_json_object_begin_trace {0};
static std::atomic<uint32_t> g_json_object_find_trace {0};
static std::atomic<uint32_t> g_json_pair_trace {0};

struct JsonValue;

struct JsonString {
	std::string* impl;
};

struct JsonArray {
	std::vector<JsonValue*>* impl;
};

struct JsonArrayIterator {
	JsonValue* const* position;
};

struct JsonObject {
	std::map<std::string, JsonValue*>* impl;
};

struct JsonValue {
	JsonValue* parent;
	void*      rootparam;
	union {
		bool        boolean;
		int64_t     integer;
		uint64_t    uinteger;
		double      real;
		JsonString* string;
		JsonArray*  array;
		JsonObject* object;
	};
	char     padding[4];
	uint32_t type;
};

// Object::Pair as reached through an iterator: key at 0, value at 0x10, native leaves 8 unused.
// map stores &value: getValue and an iterator hand out the same address
struct JsonObjectPair {
	JsonString                         key;
	std::map<std::string, JsonValue*>* owner;
	JsonValue                          value;
};

// Iterator heap cell: 0 released (or zeroed guest memory), JSON_OBJECT_ITERATOR_SINGULAR no node,
// aligned JsonObjectPair* an element, map | 1 the end node.
struct JsonObjectIterator {
	uintptr_t word;
};

constexpr uintptr_t JSON_OBJECT_ITERATOR_SINGULAR = 1;

static_assert(sizeof(JsonArray) == 8);
static_assert(sizeof(JsonArrayIterator) == 8);
static_assert(sizeof(JsonValue) == 32 && offsetof(JsonValue, type) == 28);
static_assert(sizeof(JsonObjectPair) == 0x30 && offsetof(JsonObjectPair, value) == 0x10);
static_assert(sizeof(JsonObjectIterator) == 8);

struct JsonInitParameter2 {
	void*    allocator;
	void*    user_data;
	size_t   file_buffer_size;
	uint32_t special_float_format_type;
	uint32_t reserved[3];
};

struct JsonInitParameter {
	void*  allocator;
	void*  user_data;
	size_t file_buffer_size;
};

using JsonSerializeCallback = int32_t(KYTY_SYSV_ABI*)(JsonString* str, void* context);
using JsonParseRead         = int32_t(KYTY_SYSV_ABI*)(char* out, void* context);
// The guest returns the replacement Value through result; failed set by the handler aborts the
// serialize.
using JsonSpecialFloatHandler = JsonValue*(KYTY_SYSV_ABI*)(JsonValue * result, int32_t func_type,
                                                           double value, const JsonValue* parent,
                                                           void* context, bool* failed);

// One copy per guest process, like the native library's globals.
static bool                    g_json_initialized           = false;
static bool                    g_json_init_parameter2       = false;
static size_t                  g_json_file_buffer_size      = 0;
static uint32_t                g_json_special_float_format  = 2;
static JsonSpecialFloatHandler g_json_special_float_handler = nullptr;
static void*                   g_json_special_float_context = nullptr;
static bool                    g_json_special_float_active  = false;
static void*                   g_json_null_access_callback  = nullptr;

static int32_t JsonNotInitialized(const char* function) {
	const auto trace = g_json_noinit_trace.fetch_add(1, std::memory_order_relaxed);
	if (trace < 64) {
		LOGF("JSON2_NOT_INITIALIZED trace=%u function=%s\n", trace, function);
	}
	return JSON_ERROR_NOINIT;
}

// c_str hands the guest a pointer into the host heap; IPMI copyin accepts spans inside the ranges handed out.
static std::mutex                  g_cstr_mutex;
static std::map<uintptr_t, size_t> g_cstr_ranges;

static void JsonExposeCStr(const std::string* text) {
	const auto      start = reinterpret_cast<uintptr_t>(text->c_str());
	const auto      end   = start + text->size() + 1;
	std::lock_guard lock(g_cstr_mutex);
	auto            it = g_cstr_ranges.upper_bound(start);
	if (it != g_cstr_ranges.begin() && std::prev(it)->first + std::prev(it)->second > start) --it;
	while (it != g_cstr_ranges.end() && it->first < end) it = g_cstr_ranges.erase(it);
	g_cstr_ranges.emplace(start, end - start);
}

static void JsonForgetCStr(const std::string* text) {
	if (text == nullptr) return;
	std::lock_guard lock(g_cstr_mutex);
	g_cstr_ranges.erase(reinterpret_cast<uintptr_t>(text->c_str()));
}

bool ContainsCString(const void* pointer, uint64_t size) {
	const auto      address = reinterpret_cast<uintptr_t>(pointer);
	std::lock_guard lock(g_cstr_mutex);
	auto            it = g_cstr_ranges.upper_bound(address);
	if (it == g_cstr_ranges.begin()) return false;
	--it;
	const auto offset = address - it->first;
	return offset < it->second && size <= it->second - offset;
}

static std::string* JsonStringImpl(JsonString* self) {
	if (self == nullptr) {
		return nullptr;
	}
	if (self->impl == nullptr) {
		self->impl = new std::string;
	}
	return self->impl;
}

static const std::string* JsonStringImpl(const JsonString* self) {
	static const std::string empty;
	return (self != nullptr && self->impl != nullptr ? self->impl : &empty);
}

static std::vector<JsonValue*>* JsonArrayImpl(JsonArray* self) {
	if (self == nullptr) {
		return nullptr;
	}
	if (self->impl == nullptr) {
		self->impl = new std::vector<JsonValue*>;
	}
	return self->impl;
}

static const std::vector<JsonValue*>* JsonArrayImpl(const JsonArray* self) {
	static const std::vector<JsonValue*> empty;
	return (self != nullptr && self->impl != nullptr ? self->impl : &empty);
}

// Objects reached through a JsonValue's union are Kyty-heap allocations. A guest that bitwise-copies
// a value and then destroys one copy leaves the other with a dangling object pointer whose type still
// reads Object, so dereferencing self->object->impl walks a freed std::map. Track the ones we allocate
// so a stale handle resolves to an empty object instead of faulting the whole emulator.
static std::mutex                             g_live_objects_mutex;
static std::unordered_set<const JsonObject*>  g_live_objects;

static JsonObject* JsonObjectTrack(JsonObject* self) {
	if (self != nullptr) {
		std::scoped_lock lock(g_live_objects_mutex);
		g_live_objects.insert(self);
	}
	return self;
}

static void JsonObjectForget(const JsonObject* self) {
	if (self != nullptr) {
		std::scoped_lock lock(g_live_objects_mutex);
		g_live_objects.erase(self);
	}
}

static bool JsonObjectIsLive(const JsonObject* self) {
	std::scoped_lock lock(g_live_objects_mutex);
	return g_live_objects.find(self) != g_live_objects.end();
}

static std::map<std::string, JsonValue*>* JsonObjectImpl(JsonObject* self) {
	if (self == nullptr) {
		return nullptr;
	}
	if (self->impl == nullptr) {
		self->impl = new std::map<std::string, JsonValue*>;
	}
	return self->impl;
}

static const std::map<std::string, JsonValue*>* JsonObjectImpl(const JsonObject* self) {
	static const std::map<std::string, JsonValue*> empty;
	return (self != nullptr && self->impl != nullptr ? self->impl : &empty);
}

// For dereferences of a JsonValue's object field, where a dangling handle is possible.
static const std::map<std::string, JsonValue*>* JsonValueObjectImpl(const JsonObject* self) {
	static const std::map<std::string, JsonValue*> empty;
	return JsonObjectIsLive(self) ? JsonObjectImpl(self) : &empty;
}

static JsonValue* JsonStaticNullValue() {
	static JsonValue value {};
	return &value;
}

static JsonString* JsonStaticString() {
	static JsonString str {new std::string};
	return &str;
}

static JsonArray* JsonStaticArray() {
	static JsonArray array {new std::vector<JsonValue*>};
	return &array;
}

static JsonObject* JsonStaticObject() {
	static JsonObject object {new std::map<std::string, JsonValue*>};
	return JsonObjectTrack(&object);
}

static void JsonValueInit(JsonValue* self) {
	if (self != nullptr) {
		std::memset(self, 0, sizeof(JsonValue));
		self->type = JsonValueTypeNull;
	}
}

static void JsonValueClear(JsonValue* self);
static void JsonValueCopy(JsonValue* dst, const JsonValue* src);

static JsonValue* JsonValueNew() {
	auto* value = new JsonValue;
	JsonValueInit(value);
	return value;
}

static JsonString* JsonStringNew(const std::string& value) {
	auto* str = new JsonString {};
	str->impl = new std::string(value);
	return str;
}

static JsonArray* JsonArrayNew() {
	auto* array = new JsonArray {};
	array->impl = new std::vector<JsonValue*>;
	return array;
}

static JsonObject* JsonObjectNew() {
	auto* object = new JsonObject {};
	object->impl = new std::map<std::string, JsonValue*>;
	return JsonObjectTrack(object);
}

// Callers only insert keys that are absent from impl.
static JsonValue* JsonObjectPairNew(std::map<std::string, JsonValue*>* impl,
                                    const std::string&                 key) {
	auto* pair = new JsonObjectPair {};
	auto  it   = impl->emplace(key, &pair->value).first;
	// borrows the node key, destroying or reassigning it corrupts the map
	pair->key.impl = const_cast<std::string*>(&it->first);
	pair->owner    = impl;
	return &pair->value;
}

static JsonObjectPair* JsonObjectPairOf(JsonValue* value) {
	return reinterpret_cast<JsonObjectPair*>(reinterpret_cast<char*>(value) -
	                                         offsetof(JsonObjectPair, value));
}

static void JsonObjectPairDelete(JsonValue* value) {
	JsonValueClear(value);
	delete JsonObjectPairOf(value);
}

static std::vector<JsonValue*>* JsonArrayCopy(const JsonArray* src, JsonValue* parent) {
	auto* impl = new std::vector<JsonValue*>;
	for (const auto* value: *JsonArrayImpl(src)) {
		auto* copy = JsonValueNew();
		JsonValueCopy(copy, value);
		copy->parent = parent;
		impl->push_back(copy);
	}
	return impl;
}

static std::map<std::string, JsonValue*>* JsonObjectCopy(const JsonObject* src, JsonValue* parent) {
	auto* impl = new std::map<std::string, JsonValue*>;
	for (const auto& [key, value]: *JsonObjectImpl(src)) {
		auto* copy = JsonObjectPairNew(impl, key);
		JsonValueCopy(copy, value);
		copy->parent = parent;
	}
	return impl;
}

static void JsonValueSetEmptyType(JsonValue* self, uint32_t type) {
	if (self == nullptr) {
		return;
	}
	self->type = type;
	switch (type) {
		case JsonValueTypeString: self->string = JsonStringNew(""); break;
		case JsonValueTypeArray: self->array = JsonArrayNew(); break;
		case JsonValueTypeObject: self->object = JsonObjectNew(); break;
		default: self->uinteger = 0; break;
	}
}

static void JsonValueDelete(JsonValue* self) {
	if (self != nullptr) {
		JsonValueClear(self);
		delete self;
	}
}

static void JsonStringDelete(JsonString* self) {
	if (self != nullptr) {
		JsonForgetCStr(self->impl);
		delete self->impl;
		delete self;
	}
}

static void JsonArrayDestroy(JsonArray* self) {
	if (self != nullptr) {
		if (self->impl != nullptr) {
			for (auto* value: *self->impl) {
				JsonValueDelete(value);
			}
		}
		delete self->impl;
		self->impl = nullptr;
	}
}

static void JsonObjectDestroy(JsonObject* self) {
	if (self != nullptr) {
		if (self->impl != nullptr) {
			for (auto& item: *self->impl) {
				JsonObjectPairDelete(item.second);
			}
		}
		delete self->impl;
		self->impl = nullptr;
	}
}

static void JsonValueClear(JsonValue* self) {
	if (self == nullptr) {
		return;
	}

	switch (self->type) {
		case JsonValueTypeString: JsonStringDelete(self->string); break;
		case JsonValueTypeArray:
			JsonArrayDestroy(self->array);
			delete self->array;
			break;
		case JsonValueTypeObject:
			JsonObjectDestroy(self->object);
			JsonObjectForget(self->object);
			delete self->object;
			break;
		default: break;
	}

	self->parent    = nullptr;
	self->rootparam = nullptr;
	self->uinteger  = 0;
	self->type      = JsonValueTypeNull;
}

static void JsonValueCopy(JsonValue* dst, const JsonValue* src) {
	if (dst == nullptr || src == nullptr || dst == src) {
		return;
	}

	// Native set() keeps a container of the same type and assigns into it, so a String/Array/Object pointer taken with refer*() stays valid across the set (SystemLogger2 relies on this).
	if (dst->type == src->type) {
		switch (src->type) {
			case JsonValueTypeString: {
				std::string text = *JsonStringImpl(src->string);
				JsonForgetCStr(dst->string->impl);
				*JsonStringImpl(dst->string) = std::move(text);
				return;
			}
			case JsonValueTypeArray: {
				auto* impl = JsonArrayCopy(src->array, dst);
				JsonArrayDestroy(dst->array);
				dst->array->impl = impl;
				return;
			}
			case JsonValueTypeObject: {
				auto* impl = JsonObjectCopy(src->object, dst);
				JsonObjectDestroy(dst->object);
				dst->object->impl = impl;
				return;
			}
			default: break;
		}
	}

	JsonValueClear(dst);
	dst->type = src->type;
	switch (src->type) {
		case JsonValueTypeBoolean: dst->boolean = src->boolean; break;
		case JsonValueTypeInteger: dst->integer = src->integer; break;
		case JsonValueTypeUInteger: dst->uinteger = src->uinteger; break;
		case JsonValueTypeReal: dst->real = src->real; break;
		case JsonValueTypeString: dst->string = JsonStringNew(*JsonStringImpl(src->string)); break;
		case JsonValueTypeArray: dst->array = new JsonArray {JsonArrayCopy(src->array, dst)}; break;
		case JsonValueTypeObject:
			dst->object = JsonObjectTrack(new JsonObject {JsonObjectCopy(src->object, dst)});
			break;
		default: dst->uinteger = 0; break;
	}
}

static JsonValue* JsonObjectLookup(JsonObject* object, const std::string& key, bool create) {
	auto* impl = JsonObjectImpl(object);
	if (impl == nullptr) {
		return JsonStaticNullValue();
	}
	auto it = impl->find(key);
	if (it != impl->end()) {
		return it->second;
	}
	if (!create) {
		return JsonStaticNullValue();
	}
	return JsonObjectPairNew(impl, key);
}

static bool JsonValueFromNlohmann(JsonValue* out, const nlohmann::json& value) {
	if (out == nullptr) {
		return false;
	}

	JsonValueClear(out);
	if (value.is_null()) {
		return true;
	}
	if (value.is_boolean()) {
		out->type    = JsonValueTypeBoolean;
		out->boolean = value.get<bool>();
		return true;
	}
	if (value.is_number_integer() && !value.is_number_unsigned()) {
		out->type    = JsonValueTypeInteger;
		out->integer = value.get<int64_t>();
		return true;
	}
	if (value.is_number_unsigned()) {
		out->type     = JsonValueTypeUInteger;
		out->uinteger = value.get<uint64_t>();
		return true;
	}
	if (value.is_number_float()) {
		out->type = JsonValueTypeReal;
		out->real = value.get<double>();
		return true;
	}
	if (value.is_string()) {
		out->type   = JsonValueTypeString;
		out->string = JsonStringNew(value.get_ref<const std::string&>());
		return true;
	}
	if (value.is_array()) {
		out->type  = JsonValueTypeArray;
		out->array = JsonArrayNew();
		for (const auto& item: value) {
			auto* child = JsonValueNew();
			if (!JsonValueFromNlohmann(child, item)) {
				JsonValueDelete(child);
				return false;
			}
			child->parent = out;
			out->array->impl->push_back(child);
		}
		return true;
	}
	if (value.is_object()) {
		out->type   = JsonValueTypeObject;
		out->object = JsonObjectNew();
		for (auto it = value.begin(); it != value.end(); ++it) {
			// A failed child is already in the map and goes away when the caller clears the root.
			auto* child = JsonObjectPairNew(out->object->impl, it.key());
			if (!JsonValueFromNlohmann(child, *it)) {
				return false;
			}
			child->parent = out;
		}
		return true;
	}
	return false;
}

static void JsonValueAppendText(const JsonValue* self, std::string* out) {
	char text[256];
	switch (self->type) {
		case JsonValueTypeNull: out->append("null"); break;
		case JsonValueTypeBoolean: out->append(self->boolean ? "true" : "false"); break;
		case JsonValueTypeInteger:
			std::snprintf(text, sizeof(text), "%" PRId64, self->integer);
			out->append(text);
			break;
		case JsonValueTypeUInteger:
			std::snprintf(text, sizeof(text), "%" PRIu64, self->uinteger);
			out->append(text);
			break;
		case JsonValueTypeReal: {
			if (!std::isfinite(self->real)) {
				// UCRT prints a negative NaN as -nan(ind), so the non-finite text never goes
				// through snprintf.
				const char* name =
				    (std::isnan(self->real) ? "nan" : (self->real > 0 ? "inf" : "-inf"));
				if (g_json_init_parameter2 && g_json_special_float_format == 1) {
					out->append("null");
				} else if (g_json_init_parameter2 && g_json_special_float_format == 0) {
					out->push_back('"');
					out->append(name);
					out->push_back('"');
				} else {
					out->append(name);
				}
				break;
			}
			std::snprintf(text, sizeof(text), g_json_init_parameter2 ? "%1.17g" : "%f", self->real);
			if (char* point = std::strchr(text, '.');
			    point != nullptr && std::strspn(point + 1, "0") == std::strlen(point + 1)) {
				*point = 0;
			}
			out->append(text);
			break;
		}
		case JsonValueTypeString: out->append(*JsonStringImpl(self->string)); break;
		case JsonValueTypeArray: out->append("array"); break;
		case JsonValueTypeObject: out->append("object"); break;
		default: break;
	}
}

static void JsonAppendQuoted(std::string* out, const std::string& text) {
	out->push_back('"');
	for (const char c: text) {
		switch (c) {
			case '\b': out->append("\\b"); break;
			case '\t': out->append("\\t"); break;
			case '\n': out->append("\\n"); break;
			case '\f': out->append("\\f"); break;
			case '\r': out->append("\\r"); break;
			case '"': out->append("\\\""); break;
			case '/': out->append("\\/"); break;
			case '\\': out->append("\\\\"); break;
			default:
				// Bytes from 0x80 up pass through raw.
				if (c == 0x7f || static_cast<uint8_t>(c) < 0x20) {
					char escape[7];
					std::snprintf(escape, sizeof(escape), "\\u%04x", static_cast<uint8_t>(c));
					out->append(escape);
				} else {
					out->push_back(c);
				}
				break;
		}
	}
	out->push_back('"');
}

struct JsonSerializeSink {
	JsonString*           dst;
	JsonSerializeCallback callback;
	void*                 context;
};

// sink gets the scratch String after every token, or dst with the token appended
static int32_t JsonSerializeEmit(JsonString* chunk, const JsonSerializeSink* sink) {
	if (sink->dst == nullptr) {
		const int32_t result = sink->callback(chunk, sink->context);
		chunk->impl->clear();
		return result;
	}
	if (sink->dst->impl != nullptr) {
		sink->dst->impl->append(*chunk->impl);
	}
	chunk->impl->clear();
	return (sink->callback != nullptr ? sink->callback(sink->dst, sink->context) : 0);
}

static int32_t JsonSerializeValue(const JsonValue* value, JsonString* chunk,
                                  const JsonSerializeSink* sink) {
	switch (value->type) {
		case JsonValueTypeNull:
		case JsonValueTypeBoolean:
		case JsonValueTypeInteger:
		case JsonValueTypeUInteger:
		case JsonValueTypeReal:
			if (value->type == JsonValueTypeReal && g_json_special_float_handler != nullptr &&
			    !std::isfinite(value->real) && !g_json_special_float_active) {
				g_json_special_float_active = true;
				bool      failed            = false;
				JsonValue replacement {};
				JsonValueInit(&replacement);
				g_json_special_float_handler(&replacement, 0, value->real, value->parent,
				                             g_json_special_float_context, &failed);
				int32_t result = JSON_ERROR_SPECIAL_FLOAT;
				if (!failed) {
					result = JsonSerializeValue(&replacement, chunk, sink);
				}
				JsonValueClear(&replacement);
				g_json_special_float_active = false;
				return result;
			}
			JsonValueAppendText(value, chunk->impl);
			return JsonSerializeEmit(chunk, sink);
		case JsonValueTypeString:
			JsonAppendQuoted(chunk->impl, *JsonStringImpl(value->string));
			return JsonSerializeEmit(chunk, sink);
		case JsonValueTypeArray: {
			chunk->impl->push_back('[');
			int32_t result = JsonSerializeEmit(chunk, sink);
			if (result < 0) {
				return result;
			}
			bool first = true;
			for (const auto* item: *JsonArrayImpl(value->array)) {
				if (!first) {
					chunk->impl->push_back(',');
				}
				first  = false;
				result = JsonSerializeValue(item, chunk, sink);
				if (result < 0) {
					return result;
				}
			}
			chunk->impl->push_back(']');
			return JsonSerializeEmit(chunk, sink);
		}
		case JsonValueTypeObject: {
			chunk->impl->push_back('{');
			int32_t result = JsonSerializeEmit(chunk, sink);
			if (result < 0) {
				return result;
			}
			bool first = true;
			for (const auto& item: *JsonValueObjectImpl(value->object)) {
				if (!first) {
					chunk->impl->push_back(',');
				}
				first = false;
				JsonAppendQuoted(chunk->impl, item.first);
				chunk->impl->push_back(':');
				result = JsonSerializeValue(item.second, chunk, sink);
				if (result < 0) {
					return result;
				}
			}
			chunk->impl->push_back('}');
			return JsonSerializeEmit(chunk, sink);
		}
		default: return 0;
	}
}

static int32_t JsonSerialize(const JsonValue* self, JsonString* dst, JsonSerializeCallback callback,
                             void* context) {
	if (!g_json_initialized) {
		return JsonNotInitialized("Value::serialize");
	}
	JsonString              chunk {new std::string};
	const JsonSerializeSink sink {dst, callback, context};
	const int32_t           result = JsonSerializeValue(self, &chunk, &sink);
	JsonForgetCStr(chunk.impl);
	delete chunk.impl;
	return result;
}

static void* KYTY_SYSV_ABI JsonMemAllocatorCtor(void* self) {
	PRINT_NAME();

	return self;
}

static JsonInitParameter2* KYTY_SYSV_ABI JsonInitParameter2Ctor(JsonInitParameter2* self) {
	PRINT_NAME();

	if (self != nullptr) {
		self->allocator                 = nullptr;
		self->user_data                 = nullptr;
		self->file_buffer_size          = 0;
		self->special_float_format_type = 0;
		self->reserved[0]               = 0;
		self->reserved[1]               = 0;
		self->reserved[2]               = 0;
	}

	return self;
}

static void KYTY_SYSV_ABI JsonInitParameter2SetAllocator(JsonInitParameter2* self, void* allocator,
                                                         void* user_data) {
	PRINT_NAME();

	if (self != nullptr) {
		self->allocator = allocator;
		self->user_data = user_data;
	}
}

static void KYTY_SYSV_ABI JsonInitParameter2SetFileBufferSize(JsonInitParameter2* self,
                                                              size_t              size) {
	PRINT_NAME();

	if (self != nullptr) {
		self->file_buffer_size = size;
	}
}

static void KYTY_SYSV_ABI JsonInitParameter2SetSpecialFloatFormatType(JsonInitParameter2* self,
                                                                      uint32_t            type) {
	PRINT_NAME();

	if (self != nullptr) {
		self->special_float_format_type = type;
	}
}

// The Initializer object is a single byte: set while this instance is the one that initialized the
// library.
static void* KYTY_SYSV_ABI JsonInitializerCtor(void* self) {
	PRINT_NAME();

	*static_cast<uint8_t*>(self) = 0;
	return self;
}

static int KYTY_SYSV_ABI JsonInitializerInitialize(void*                     self,
                                                   const JsonInitParameter2* init_param) {
	PRINT_NAME();

	auto*   active = static_cast<uint8_t*>(self);
	int32_t result = 0;
	if (g_json_initialized || *active != 0) {
		result = JSON_ERROR_MULTIPLEINIT;
	} else if (init_param == nullptr || init_param->allocator == nullptr ||
	           init_param->special_float_format_type > 2) {
		result = JSON_ERROR_INVALID_ARGUMENT;
	} else {
		g_json_initialized          = true;
		g_json_init_parameter2      = true;
		g_json_file_buffer_size     = init_param->file_buffer_size;
		g_json_special_float_format = init_param->special_float_format_type;
		*active                     = 1;
	}

	LOGF("\t self       = 0x%016" PRIx64 "\n"
	     "\t init_param = 0x%016" PRIx64 "\n"
	     "\t result     = 0x%08x\n",
	     reinterpret_cast<uint64_t>(self), reinterpret_cast<uint64_t>(init_param),
	     static_cast<uint32_t>(result));

	return result;
}

static int KYTY_SYSV_ABI JsonInitializerInitializeV1(void*                    self,
                                                     const JsonInitParameter* init_param) {
	PRINT_NAME();

	auto*   active = static_cast<uint8_t*>(self);
	int32_t result = 0;
	if (g_json_initialized || *active != 0) {
		result = JSON_ERROR_MULTIPLEINIT;
	} else if (init_param == nullptr) {
		result = JSON_ERROR_INVALID_ARGUMENT;
	} else if (init_param->allocator == nullptr) {
		result = JSON_ERROR_NOMEM;
	} else {
		g_json_initialized      = true;
		g_json_file_buffer_size = init_param->file_buffer_size;
		*active                 = 1;
	}

	LOGF("\t self       = 0x%016" PRIx64 "\n"
	     "\t init_param = 0x%016" PRIx64 "\n"
	     "\t result     = 0x%08x\n",
	     reinterpret_cast<uint64_t>(self), reinterpret_cast<uint64_t>(init_param),
	     static_cast<uint32_t>(result));

	return result;
}

static int32_t KYTY_SYSV_ABI JsonInitializerTerminate(void* self) {
	PRINT_NAME();

	LOGF("\t self = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(self));

	auto* active = static_cast<uint8_t*>(self);
	if (!g_json_initialized || *active == 0) {
		return JsonNotInitialized("Initializer::terminate");
	}
	g_json_initialized           = false;
	g_json_init_parameter2       = false;
	g_json_file_buffer_size      = 0;
	g_json_special_float_format  = 2;
	g_json_special_float_handler = nullptr;
	g_json_special_float_context = nullptr;
	g_json_null_access_callback  = nullptr;
	*active                      = 0;
	return 0;
}

static void KYTY_SYSV_ABI JsonMemAllocatorDtor(void* self) {
	PRINT_NAME();

	LOGF("\t self = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(self));
}

static void* KYTY_SYSV_ABI JsonValueCtor(void* self) {
	PRINT_NAME();

	LOGF("\t self = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(self));

	if (self != nullptr) {
		JsonValueInit(reinterpret_cast<JsonValue*>(self));
	}

	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueCopyCtor(JsonValue* self, const JsonValue* src) {
	PRINT_NAME();

	JsonValueInit(self);
	JsonValueCopy(self, src);
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueTypeCtor(JsonValue* self, uint32_t type) {
	PRINT_NAME();

	JsonValueInit(self);
	JsonValueSetEmptyType(self, type);
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueBoolCtor(JsonValue* self, bool value) {
	PRINT_NAME();

	JsonValueInit(self);
	if (self != nullptr) {
		self->type    = JsonValueTypeBoolean;
		self->boolean = value;
	}
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueIntCtor(JsonValue* self, int64_t value) {
	PRINT_NAME();

	JsonValueInit(self);
	if (self != nullptr) {
		self->type    = JsonValueTypeInteger;
		self->integer = value;
	}
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueUIntCtor(JsonValue* self, uint64_t value) {
	PRINT_NAME();

	JsonValueInit(self);
	if (self != nullptr) {
		self->type     = JsonValueTypeUInteger;
		self->uinteger = value;
	}
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueDoubleCtor(JsonValue* self, double value) {
	PRINT_NAME();

	JsonValueInit(self);
	if (self != nullptr) {
		self->type = JsonValueTypeReal;
		self->real = value;
	}
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueCStringCtor(JsonValue* self, const char* value) {
	PRINT_NAME();

	JsonValueInit(self);
	if (self != nullptr) {
		self->type   = JsonValueTypeString;
		self->string = JsonStringNew(value != nullptr ? value : "");
	}
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueStringCtor(JsonValue* self, const JsonString* value) {
	PRINT_NAME();

	JsonValueInit(self);
	if (self != nullptr) {
		self->type   = JsonValueTypeString;
		self->string = JsonStringNew(*JsonStringImpl(value));
	}
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueObjectCtor(JsonValue* self, const JsonObject* value) {
	PRINT_NAME();

	JsonValueInit(self);
	if (self != nullptr) {
		self->type   = JsonValueTypeObject;
		self->object = JsonObjectTrack(new JsonObject {JsonObjectCopy(value, self)});
	}
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonValueArrayCtor(JsonValue* self, const JsonArray* value) {
	PRINT_NAME();

	JsonValueInit(self);
	if (self != nullptr) {
		self->type  = JsonValueTypeArray;
		self->array = new JsonArray {JsonArrayCopy(value, self)};
	}
	return self;
}

static void KYTY_SYSV_ABI JsonValueSetObject(JsonValue* self, const JsonObject* value) {
	PRINT_NAME();

	if (self != nullptr) {
		// The source may be this value's object or one of its descendants.
		auto* impl = JsonObjectCopy(value, self);
		if (self->type == JsonValueTypeObject) {
			JsonObjectDestroy(self->object);
		} else {
			JsonValueClear(self);
			self->type   = JsonValueTypeObject;
			self->object = JsonObjectTrack(new JsonObject {});
		}
		self->object->impl = impl;
	}
}

static void KYTY_SYSV_ABI JsonValueSetArray(JsonValue* self, const JsonArray* value) {
	PRINT_NAME();

	if (self != nullptr && value->impl != nullptr) {
		// The source may be this value's array or one of its descendants.
		auto* impl = JsonArrayCopy(value, self);
		if (self->type == JsonValueTypeArray) {
			JsonArrayDestroy(self->array);
		} else {
			JsonValueClear(self);
			self->type  = JsonValueTypeArray;
			self->array = new JsonArray {};
		}
		self->array->impl = impl;
	}
}

static void KYTY_SYSV_ABI JsonValueDtor(void* self) {
	PRINT_NAME();

	LOGF("\t self = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(self));

	JsonValueClear(reinterpret_cast<JsonValue*>(self));
}

static JsonValue* KYTY_SYSV_ABI JsonValueAssign(JsonValue* self, const JsonValue* src) {
	PRINT_NAME();

	JsonValueCopy(self, src);
	return self;
}

static void KYTY_SYSV_ABI JsonValueSwap(JsonValue* self, JsonValue* other) {
	PRINT_NAME();

	JsonValue tmp {};
	JsonValueInit(&tmp);
	JsonValueCopy(&tmp, self);
	JsonValueCopy(self, other);
	JsonValueCopy(other, &tmp);
	JsonValueClear(&tmp);
}

static bool KYTY_SYSV_ABI JsonValueToBool(const JsonValue* self) {
	PRINT_NAME();

	switch (self->type) {
		case JsonValueTypeNull: return false;
		case JsonValueTypeBoolean: return self->boolean;
		case JsonValueTypeInteger:
		case JsonValueTypeUInteger: return self->integer != 0;
		case JsonValueTypeReal: return self->real != 0.0;
		// A String with no impl counts as non-empty here, matching the native empty().
		case JsonValueTypeString:
			return self->string != nullptr &&
			       !(self->string->impl != nullptr && self->string->impl->empty());
		default: return true;
	}
}

static void KYTY_SYSV_ABI JsonValueSetBool(JsonValue* self, bool value) {
	PRINT_NAME();

	JsonValueClear(self);
	if (self != nullptr) {
		self->type    = JsonValueTypeBoolean;
		self->boolean = value;
	}
}

static void KYTY_SYSV_ABI JsonValueSetInt(JsonValue* self, int64_t value) {
	PRINT_NAME();

	JsonValueClear(self);
	if (self != nullptr) {
		self->type    = JsonValueTypeInteger;
		self->integer = value;
	}
}

static void KYTY_SYSV_ABI JsonValueSetUInt(JsonValue* self, uint64_t value) {
	PRINT_NAME();

	JsonValueClear(self);
	if (self != nullptr) {
		self->type     = JsonValueTypeUInteger;
		self->uinteger = value;
	}
}

static void KYTY_SYSV_ABI JsonValueSetDouble(JsonValue* self, double value) {
	PRINT_NAME();

	JsonValueClear(self);
	if (self != nullptr) {
		self->type = JsonValueTypeReal;
		self->real = value;
	}
}

static void KYTY_SYSV_ABI JsonValueSetString(JsonValue* self, const JsonString* value) {
	PRINT_NAME();

	JsonValueClear(self);
	if (self != nullptr) {
		self->type   = JsonValueTypeString;
		self->string = JsonStringNew(*JsonStringImpl(value));
	}
}

static void KYTY_SYSV_ABI JsonValueSetType(JsonValue* self, uint32_t type) {
	PRINT_NAME();

	JsonValueClear(self);
	JsonValueSetEmptyType(self, type);
}

static uint32_t KYTY_SYSV_ABI JsonValueGetType(const JsonValue* self) {
	PRINT_NAME();

	return (self != nullptr ? self->type : JsonValueTypeNull);
}

static JsonArray* KYTY_SYSV_ABI JsonValueReferArray(JsonValue* self) {
	PRINT_NAME();

	return (self != nullptr && self->type == JsonValueTypeArray ? self->array : nullptr);
}

static JsonObject* KYTY_SYSV_ABI JsonValueReferObject(JsonValue* self) {
	PRINT_NAME();

	return (self != nullptr && self->type == JsonValueTypeObject ? self->object : nullptr);
}

static const JsonString* KYTY_SYSV_ABI JsonValueGetString(const JsonValue* self) {
	PRINT_NAME();

	return (self != nullptr && self->type == JsonValueTypeString ? self->string
	                                                             : JsonStaticString());
}

static const JsonArray* KYTY_SYSV_ABI JsonValueGetArray(const JsonValue* self) {
	PRINT_NAME();

	return (self != nullptr && self->type == JsonValueTypeArray ? self->array : JsonStaticArray());
}

static const JsonObject* KYTY_SYSV_ABI JsonValueGetObject(const JsonValue* self) {
	PRINT_NAME();

	return (self != nullptr && self->type == JsonValueTypeObject ? self->object
	                                                             : JsonStaticObject());
}

static const bool* KYTY_SYSV_ABI JsonValueGetBoolean(const JsonValue* self) {
	PRINT_NAME();

	static const bool false_value = false;
	return (self != nullptr && self->type == JsonValueTypeBoolean ? &self->boolean : &false_value);
}

static const int64_t* KYTY_SYSV_ABI JsonValueGetInteger(const JsonValue* self) {
	PRINT_NAME();

	static const int64_t zero = 0;
	if (self != nullptr &&
	    (self->type == JsonValueTypeInteger || self->type == JsonValueTypeUInteger)) {
		return &self->integer;
	}
	return &zero;
}

static const uint64_t* KYTY_SYSV_ABI JsonValueGetUInteger(const JsonValue* self) {
	PRINT_NAME();

	static const uint64_t zero = 0;
	if (self != nullptr &&
	    (self->type == JsonValueTypeInteger || self->type == JsonValueTypeUInteger)) {
		return &self->uinteger;
	}
	return &zero;
}

static const double* KYTY_SYSV_ABI JsonValueGetReal(const JsonValue* self) {
	PRINT_NAME();

	static const double zero = 0.0;
	return (self != nullptr && self->type == JsonValueTypeReal ? &self->real : &zero);
}

static const JsonValue* KYTY_SYSV_ABI JsonValueIndexString(const JsonValue* self, const char* key) {
	PRINT_NAME();

	if (self == nullptr || self->type != JsonValueTypeObject) {
		return JsonStaticNullValue();
	}
	return JsonObjectLookup(self->object, key != nullptr ? key : "", false);
}

static const JsonValue* KYTY_SYSV_ABI JsonValueIndexUInt(const JsonValue* self, uint64_t index) {
	PRINT_NAME();

	if (self == nullptr || self->type != JsonValueTypeArray) {
		return JsonStaticNullValue();
	}
	const auto* impl = JsonArrayImpl(self->array);
	return (index < impl->size() ? (*impl)[static_cast<size_t>(index)] : JsonStaticNullValue());
}

static const JsonValue* KYTY_SYSV_ABI JsonValueGetValue(const JsonValue*  self,
                                                        const JsonString* key) {
	PRINT_NAME();

	const JsonValue* result       = nullptr;
	const char*      branch       = "key_unset";
	size_t           key_length   = 0;
	size_t           object_count = 0;

	if (key != nullptr && key->impl != nullptr) {
		key_length = key->impl->size();
		if (self == nullptr || self->type != JsonValueTypeObject) {
			branch = "wrong_parent_type";
		} else {
			const auto* impl = JsonValueObjectImpl(self->object);
			object_count     = impl->size();
			const auto it    = impl->find(*key->impl);
			if (it != impl->end()) {
				result = it->second;
				branch = "hit";
			} else {
				branch = "missing";
			}
		}
	}
	if (result == nullptr) result = JsonStaticNullValue();

	const auto trace = g_json_lookup_trace.fetch_add(1, std::memory_order_relaxed);
	if (trace < 128) {
		LOGF("JSON2_LOOKUP_BOUNDARY provider=hle_msmo trace=%u key_storage=hle key_length=%" PRIu64
		     " parent_type=%u object_count=%" PRIu64 " branch=%s result_type=%u\n",
		     trace, static_cast<uint64_t>(key_length), self != nullptr ? self->type : UINT32_MAX,
		     static_cast<uint64_t>(object_count), branch, result->type);
	}
	return result;
}

static JsonValue* KYTY_SYSV_ABI JsonValueReferValueKey(JsonValue* self, const JsonString* key) {
	PRINT_NAME();

	if (self == nullptr || self->type != JsonValueTypeObject) {
		return nullptr;
	}
	const auto* impl = JsonValueObjectImpl(self->object);
	const auto  it   = impl->find(*JsonStringImpl(key));
	return (it != impl->end() ? it->second : nullptr);
}

static JsonValue* KYTY_SYSV_ABI JsonValueReferValueIndex(JsonValue* self, uint64_t index) {
	PRINT_NAME();

	if (self->type == JsonValueTypeObject) {
		const auto* impl = JsonValueObjectImpl(self->object);
		if (index < impl->size()) {
			return std::next(impl->begin(), static_cast<ptrdiff_t>(index))->second;
		}
	} else if (self->type == JsonValueTypeArray) {
		const auto* impl = JsonArrayImpl(self->array);
		if (index < impl->size()) {
			return (*impl)[index];
		}
	}
	return nullptr;
}

static JsonString* KYTY_SYSV_ABI JsonValueReferString(JsonValue* self) {
	PRINT_NAME();

	return (self != nullptr && self->type == JsonValueTypeString ? self->string : nullptr);
}

// Appends; a caller that wants only this value's text passes an empty String.
static void KYTY_SYSV_ABI JsonValueToString(const JsonValue* self, JsonString* dst) {
	PRINT_NAME();

	if (dst->impl != nullptr) {
		JsonValueAppendText(self, dst->impl);
	}
}

static int32_t KYTY_SYSV_ABI JsonValueSerialize(JsonValue* self, JsonString* dst) {
	PRINT_NAME();

	return JsonSerialize(self, dst, nullptr, nullptr);
}

static int32_t KYTY_SYSV_ABI JsonValueSerializeStringCallback(JsonValue* self, JsonString* dst,
                                                              JsonSerializeCallback callback,
                                                              void*                 context) {
	PRINT_NAME();

	return JsonSerialize(self, dst, callback, context);
}

static int32_t KYTY_SYSV_ABI JsonValueSerializeCallback(JsonValue*            self,
                                                        JsonSerializeCallback callback,
                                                        void*                 context) {
	PRINT_NAME();

	return JsonSerialize(self, nullptr, callback, context);
}

static int32_t KYTY_SYSV_ABI JsonValueSetNullAccessCallback(JsonValue* self, void* callback,
                                                            void* context) {
	PRINT_NAME();

	int32_t result = 0;
	if (self->parent != nullptr) {
		result = JSON_ERROR_NOROOT;
	} else if (!g_json_initialized) {
		result = JSON_ERROR_NOINIT;
	}

	LOGF("JSON2_NULL_ACCESS_CALLBACK scope=value value=0x%016" PRIx64 " callback=0x%016" PRIx64
	     " context=0x%016" PRIx64 " result=0x%08x invocation=not_modelled\n",
	     reinterpret_cast<uint64_t>(self), reinterpret_cast<uint64_t>(callback),
	     reinterpret_cast<uint64_t>(context), static_cast<uint32_t>(result));

	return result;
}

static JsonString* KYTY_SYSV_ABI JsonStringCtor(JsonString* self) {
	PRINT_NAME();

	if (self != nullptr) {
		self->impl = new std::string;
	}
	return self;
}

static JsonString* KYTY_SYSV_ABI JsonStringCStringCtor(JsonString* self, const char* str) {
	PRINT_NAME();

	if (self != nullptr) {
		self->impl = new std::string(str != nullptr ? str : "");
	}
	return self;
}

static JsonString* KYTY_SYSV_ABI JsonStringCopyCtor(JsonString* self, const JsonString* src) {
	PRINT_NAME();

	if (self != nullptr) {
		self->impl =
		    (src != nullptr && src->impl != nullptr ? new std::string(*src->impl) : nullptr);
	}

	const auto trace = g_json_pair_trace.fetch_add(1, std::memory_order_relaxed);
	if (trace < 256) {
		LOGF(
		    "JSON2_PAIR_BOUNDARY provider=hle trace=%u op=string_copy source_set=%u length=%" PRIu64
		    "\n",
		    trace, src != nullptr && src->impl != nullptr ? 1u : 0u,
		    static_cast<uint64_t>(src != nullptr && src->impl != nullptr ? src->impl->size() : 0));
	}
	return self;
}

static void KYTY_SYSV_ABI JsonStringDtor(JsonString* self) {
	PRINT_NAME();

	if (self != nullptr) {
		JsonForgetCStr(self->impl);
		delete self->impl;
		self->impl = nullptr;
	}
}

static JsonString* KYTY_SYSV_ABI JsonStringAssign(JsonString* self, const JsonString* src) {
	PRINT_NAME();

	auto* impl = JsonStringImpl(self);
	if (impl != nullptr) {
		*impl = *JsonStringImpl(src);
	}
	return self;
}

static const char* KYTY_SYSV_ABI JsonStringCStr(const JsonString* self) {
	PRINT_NAME();

	const auto* impl = JsonStringImpl(self);
	JsonExposeCStr(impl);
	return impl->c_str();
}

static size_t KYTY_SYSV_ABI JsonStringLength(const JsonString* self) {
	PRINT_NAME();

	return JsonStringImpl(self)->length();
}

// Native compares are false on a null impl, so an unset String never equals "".
static bool KYTY_SYSV_ABI JsonStringEqualCString(const JsonString* self, const char* str) {
	PRINT_NAME();

	return self->impl != nullptr && std::strcmp(self->impl->c_str(), str) == 0;
}

static bool KYTY_SYSV_ABI JsonStringEqual(const JsonString* self, const JsonString* other) {
	PRINT_NAME();

	return self->impl != nullptr && other->impl != nullptr &&
	       std::strcmp(self->impl->c_str(), other->impl->c_str()) == 0;
}

// False on a null impl, unlike Array::empty and Object::empty.
static bool KYTY_SYSV_ABI JsonStringEmpty(const JsonString* self) {
	PRINT_NAME();

	return self->impl != nullptr && self->impl->empty();
}

static JsonString* KYTY_SYSV_ABI JsonStringAppend(JsonString* self, const JsonString* other) {
	PRINT_NAME();

	if (self->impl != nullptr) {
		self->impl->append(*JsonStringImpl(other));
	}
	return self;
}

static JsonString* KYTY_SYSV_ABI JsonStringAppendCString(JsonString* self, const char* str) {
	PRINT_NAME();

	if (self->impl != nullptr) {
		self->impl->append(str);
	}
	return self;
}

static JsonString* KYTY_SYSV_ABI JsonStringAppendBytes(JsonString* self, const char* str,
                                                       size_t size) {
	PRINT_NAME();

	if (self->impl != nullptr) {
		self->impl->append(str, size);
	}
	return self;
}

static void KYTY_SYSV_ABI JsonStringClear(JsonString* self) {
	PRINT_NAME();

	if (self->impl != nullptr) {
		self->impl->clear();
	}
}

// Returns the unsigned byte difference at the first mismatch, not a sign.
static int32_t KYTY_SYSV_ABI JsonStringCompareCString(const JsonString* self, const char* str) {
	PRINT_NAME();

	if (self->impl == nullptr) {
		return 0;
	}
	const auto* a = reinterpret_cast<const uint8_t*>(self->impl->c_str());
	const auto* b = reinterpret_cast<const uint8_t*>(str != nullptr ? str : "");
	while (*a != 0 && *a == *b) {
		a++;
		b++;
	}
	return static_cast<int32_t>(*a) - static_cast<int32_t>(*b);
}

static size_t KYTY_SYSV_ABI JsonStringFindCString(const JsonString* self, const char* str,
                                                  size_t pos) {
	PRINT_NAME();

	if (self->impl == nullptr) {
		return std::string::npos;
	}
	return self->impl->find(str, pos);
}

static JsonString* KYTY_SYSV_ABI JsonStringSubstr(JsonString* result, const JsonString* self,
                                                  size_t pos, size_t count) {
	PRINT_NAME();

	if (self->impl == nullptr) {
		result->impl = (g_json_initialized ? new std::string : nullptr);
	} else if (self->impl->size() <= pos) {
		result->impl = new std::string;
	} else {
		result->impl = new std::string(self->impl->substr(pos, count));
	}
	return result;
}

static JsonArray* KYTY_SYSV_ABI JsonArrayCtor(JsonArray* self) {
	PRINT_NAME();

	if (self != nullptr) {
		self->impl = new std::vector<JsonValue*>;
	}
	return self;
}

// Native leaves impl null when the source has none.
static JsonArray* KYTY_SYSV_ABI JsonArrayCopyCtor(JsonArray* self, const JsonArray* src) {
	PRINT_NAME();

	self->impl = (src->impl != nullptr ? JsonArrayCopy(src, nullptr) : nullptr);
	return self;
}

static void KYTY_SYSV_ABI JsonArrayDtor(JsonArray* self) {
	PRINT_NAME();

	JsonArrayDestroy(self);
}

static JsonArray* KYTY_SYSV_ABI JsonArrayAssign(JsonArray* self, const JsonArray* src) {
	PRINT_NAME();

	if (self->impl != nullptr && src->impl != nullptr) {
		auto* impl = JsonArrayCopy(src, nullptr);
		JsonArrayDestroy(self);
		self->impl = impl;
	}
	return self;
}

static JsonArray* KYTY_SYSV_ABI JsonArrayPushBack(JsonArray* self, const JsonValue* value) {
	PRINT_NAME();

	auto* impl = JsonArrayImpl(self);
	if (impl != nullptr) {
		auto* copy = JsonValueNew();
		JsonValueCopy(copy, value);
		impl->push_back(copy);
	}
	return self;
}

// Native erase frees the element and returns an iterator to the one after it.
static JsonArrayIterator* KYTY_SYSV_ABI JsonArrayErase(JsonArrayIterator* result, JsonArray* self,
                                                       const JsonArrayIterator* it) {
	PRINT_NAME();

	auto* impl  = JsonArrayImpl(self);
	auto  index = it->position - impl->data();
	JsonValueDelete(*it->position);
	impl->erase(impl->begin() + index);
	result->position = impl->data() + index;
	return result;
}

// pPs3qZTZQvQ unlinks the node after the list head, the same one front() reads, so it is a
// pop_front.
static void KYTY_SYSV_ABI JsonArrayPopFront(JsonArray* self) {
	PRINT_NAME();

	auto* impl = JsonArrayImpl(self);
	if (impl != nullptr && !impl->empty()) {
		JsonValueDelete(impl->front());
		impl->erase(impl->begin());
	}
}

static void KYTY_SYSV_ABI JsonArrayClear(JsonArray* self) {
	PRINT_NAME();

	if (self->impl != nullptr) {
		for (auto* value: *self->impl) {
			JsonValueDelete(value);
		}
		self->impl->clear();
	}
}

static bool KYTY_SYSV_ABI JsonArrayEmpty(const JsonArray* self) {
	PRINT_NAME();

	return self->impl == nullptr || self->impl->empty();
}

static JsonValue* KYTY_SYSV_ABI JsonArrayFront(const JsonArray* self) {
	PRINT_NAME();

	const auto* impl = JsonArrayImpl(self);
	return (!impl->empty() ? impl->front() : JsonStaticNullValue());
}

static JsonValue* KYTY_SYSV_ABI JsonArrayBack(const JsonArray* self) {
	PRINT_NAME();

	const auto* impl = JsonArrayImpl(self);
	return (!impl->empty() ? impl->back() : JsonStaticNullValue());
}

static size_t KYTY_SYSV_ABI JsonArraySize(const JsonArray* self) {
	PRINT_NAME();

	return JsonArrayImpl(self)->size();
}

// The non-trivial guest iterator is returned through an explicit result pointer.
static JsonArrayIterator* KYTY_SYSV_ABI JsonArrayBegin(JsonArrayIterator* result,
                                                    const JsonArray* self) {
	PRINT_NAME();

	result->position = JsonArrayImpl(self)->data();
	return result;
}

static JsonArrayIterator* KYTY_SYSV_ABI JsonArrayEnd(JsonArrayIterator* result,
                                                  const JsonArray* self) {
	PRINT_NAME();

	const auto* impl = JsonArrayImpl(self);
	result->position = impl->data();
	if (!impl->empty()) {
		result->position += impl->size();
	}
	return result;
}

static bool KYTY_SYSV_ABI JsonArrayIteratorNotEqual(const JsonArrayIterator* self,
                                                 const JsonArrayIterator* other) {
	PRINT_NAME();

	return self->position != other->position;
}

static JsonValue* KYTY_SYSV_ABI JsonArrayIteratorDereference(const JsonArrayIterator* self) {
	PRINT_NAME();

	return *self->position;
}

static JsonArrayIterator* KYTY_SYSV_ABI JsonArrayIteratorIncrement(JsonArrayIterator* self) {
	PRINT_NAME();

	++self->position;
	return self;
}

static JsonArrayIterator* KYTY_SYSV_ABI JsonArrayIteratorAssign(JsonArrayIterator*       self,
                                                                const JsonArrayIterator* other) {
	PRINT_NAME();

	self->position = other->position;
	return self;
}

static void KYTY_SYSV_ABI JsonArrayIteratorDtor(JsonArrayIterator*) {
	PRINT_NAME();
}

static JsonArrayIterator* KYTY_SYSV_ABI JsonArrayIteratorCtor(JsonArrayIterator* self) {
	PRINT_NAME();

	self->position = nullptr;
	return self;
}

static JsonArrayIterator* KYTY_SYSV_ABI JsonArrayIteratorCopyCtor(JsonArrayIterator*       self,
                                                                  const JsonArrayIterator* other) {
	PRINT_NAME();

	self->position = other->position;
	return self;
}

static JsonObject* KYTY_SYSV_ABI JsonObjectCtor(JsonObject* self) {
	PRINT_NAME();

	if (self != nullptr) {
		self->impl = new std::map<std::string, JsonValue*>;
	}
	return self;
}

static JsonObject* KYTY_SYSV_ABI JsonObjectCopyCtor(JsonObject* self, const JsonObject* src) {
	PRINT_NAME();

	if (self != nullptr) {
		self->impl = JsonObjectCopy(src, nullptr);
	}
	return self;
}

static void KYTY_SYSV_ABI JsonObjectDtor(JsonObject* self) {
	PRINT_NAME();

	JsonObjectDestroy(self);
}

static JsonObject* KYTY_SYSV_ABI JsonObjectAssign(JsonObject* self, const JsonObject* src) {
	PRINT_NAME();

	if (self != nullptr) {
		auto* impl = JsonObjectCopy(src, nullptr);
		JsonObjectDestroy(self);
		self->impl = impl;
	}
	return self;
}

static JsonValue* KYTY_SYSV_ABI JsonObjectIndex(JsonObject* self, const JsonString* key) {
	PRINT_NAME();

	return JsonObjectLookup(self, *JsonStringImpl(key), true);
}

static void KYTY_SYSV_ABI JsonObjectClear(JsonObject* self) {
	PRINT_NAME();

	auto* impl = JsonObjectImpl(self);
	if (impl != nullptr) {
		for (auto& item: *impl) {
			JsonObjectPairDelete(item.second);
		}
		impl->clear();
	}
}

static uintptr_t JsonObjectIteratorWord(std::map<std::string, JsonValue*>*          impl,
                                        std::map<std::string, JsonValue*>::iterator it) {
	return (it != impl->end() ? reinterpret_cast<uintptr_t>(JsonObjectPairOf(it->second))
	                          : reinterpret_cast<uintptr_t>(impl) | 1u);
}

static size_t KYTY_SYSV_ABI JsonObjectSize(const JsonObject* self) {
	PRINT_NAME();

	return (self->impl != nullptr ? self->impl->size() : 0);
}

static bool KYTY_SYSV_ABI JsonObjectEmpty(const JsonObject* self) {
	PRINT_NAME();

	return self->impl == nullptr || self->impl->empty();
}

// An existing key keeps its value; the returned iterator points at the entry either way.
static JsonObjectIterator* KYTY_SYSV_ABI JsonObjectInsert(JsonObjectIterator*   result,
                                                          JsonObject*           self,
                                                          const JsonObjectPair* pair) {
	PRINT_NAME();

	result->word = JSON_OBJECT_ITERATOR_SINGULAR;
	if (self->impl != nullptr) {
		const std::string& key = *JsonStringImpl(&pair->key);
		auto               it  = self->impl->find(key);
		if (it == self->impl->end()) {
			JsonValueCopy(JsonObjectPairNew(self->impl, key), &pair->value);
			it = self->impl->find(key);
		}
		result->word = JsonObjectIteratorWord(self->impl, it);
	}
	return result;
}

static void KYTY_SYSV_ABI JsonObjectErase(JsonObject* self, const JsonString* key) {
	PRINT_NAME();

	if (self->impl != nullptr && key->impl != nullptr) {
		auto it = self->impl->find(*key->impl);
		if (it != self->impl->end()) {
			auto* value = it->second;
			self->impl->erase(it);
			JsonObjectPairDelete(value);
		}
	}
}

static JsonObjectIterator* KYTY_SYSV_ABI JsonObjectBegin(JsonObjectIterator* result,
                                                         const JsonObject*   self) {
	PRINT_NAME();

	const char* branch       = "object_unset";
	size_t      object_count = 0;
	uint32_t    first_type   = UINT32_MAX;

	result->word = JSON_OBJECT_ITERATOR_SINGULAR;
	if (self->impl != nullptr) {
		object_count = self->impl->size();
		result->word = JsonObjectIteratorWord(self->impl, self->impl->begin());
		branch       = "empty";
		if (object_count != 0) {
			branch     = "element";
			first_type = self->impl->begin()->second->type;
		}
	}

	const auto trace = g_json_object_begin_trace.fetch_add(1, std::memory_order_relaxed);
	if (trace < 128) {
		LOGF("JSON2_OBJECT_ITER_BOUNDARY provider=hle trace=%u op=begin object_count=%" PRIu64
		     " branch=%s first_value_type=%u\n",
		     trace, static_cast<uint64_t>(object_count), branch, first_type);
	}
	return result;
}

static JsonObjectIterator* KYTY_SYSV_ABI JsonObjectEnd(JsonObjectIterator* result,
                                                       const JsonObject*   self) {
	PRINT_NAME();

	result->word = (self->impl != nullptr ? reinterpret_cast<uintptr_t>(self->impl) | 1u
	                                      : JSON_OBJECT_ITERATOR_SINGULAR);
	return result;
}

static JsonObjectIterator* KYTY_SYSV_ABI JsonObjectFind(JsonObjectIterator* result,
                                                        const JsonObject*   self,
                                                        const JsonString*   key) {
	PRINT_NAME();

	const char* branch       = "object_unset";
	size_t      key_length   = 0;
	size_t      object_count = 0;
	uint32_t    result_type  = UINT32_MAX;

	result->word = JSON_OBJECT_ITERATOR_SINGULAR;
	if (self->impl != nullptr) {
		branch       = "key_unset";
		object_count = self->impl->size();
		if (key->impl != nullptr) {
			key_length    = key->impl->size();
			const auto it = self->impl->find(*key->impl);
			result->word  = JsonObjectIteratorWord(self->impl, it);
			branch        = "missing";
			if (it != self->impl->end()) {
				branch      = "hit";
				result_type = it->second->type;
			}
		}
	}

	const auto trace = g_json_object_find_trace.fetch_add(1, std::memory_order_relaxed);
	if (trace < 128) {
		LOGF("JSON2_OBJECT_ITER_BOUNDARY provider=hle trace=%u op=find key_length=%" PRIu64
		     " object_count=%" PRIu64 " branch=%s result_type=%u\n",
		     trace, static_cast<uint64_t>(key_length), static_cast<uint64_t>(object_count), branch,
		     result_type);
	}
	return result;
}

static JsonObjectIterator* KYTY_SYSV_ABI JsonObjectIteratorCtor(JsonObjectIterator* self) {
	PRINT_NAME();

	self->word = JSON_OBJECT_ITERATOR_SINGULAR;
	return self;
}

static JsonObjectIterator* KYTY_SYSV_ABI JsonObjectIteratorCopyCtor(JsonObjectIterator*       self,
                                                                    const JsonObjectIterator* src) {
	PRINT_NAME();

	self->word = src->word;
	return self;
}

static void KYTY_SYSV_ABI JsonObjectIteratorDtor(JsonObjectIterator* self) {
	PRINT_NAME();

	self->word = 0;
}

static JsonObjectIterator* KYTY_SYSV_ABI JsonObjectIteratorAssign(JsonObjectIterator*       self,
                                                                  const JsonObjectIterator* src) {
	PRINT_NAME();

	// Native frees the destination cell when the source has no cell or no node, and ignores a
	// destination without a cell.
	if (self->word != 0) {
		self->word = (src->word != JSON_OBJECT_ITERATOR_SINGULAR ? src->word : 0);
	}
	return self;
}

static void JsonObjectIteratorStep(JsonObjectIterator* self) {
	if (self->word == 0 || self->word == JSON_OBJECT_ITERATOR_SINGULAR) {
		return;
	}
	if ((self->word & 1u) != 0) {
		EXIT("JSON2_OBJECT_ITER_BOUNDARY provider=hle op=increment branch=end "
		     "native_assert=getnext_nil\n");
	}
	auto* pair = reinterpret_cast<JsonObjectPair*>(self->word);
	auto  it   = pair->owner->find(*pair->key.impl);
	self->word = JsonObjectIteratorWord(pair->owner, ++it);
}

static JsonObjectIterator* KYTY_SYSV_ABI JsonObjectIteratorIncrement(JsonObjectIterator* self) {
	PRINT_NAME();

	JsonObjectIteratorStep(self);
	return self;
}

static void KYTY_SYSV_ABI JsonObjectIteratorAdvance(JsonObjectIterator* self, uint64_t count) {
	PRINT_NAME();

	for (uint64_t i = 0; i < count && self->word != 0; i++) {
		JsonObjectIteratorStep(self);
	}
}

static bool KYTY_SYSV_ABI JsonObjectIteratorEqual(const JsonObjectIterator* self,
                                                  const JsonObjectIterator* other) {
	PRINT_NAME();

	return self->word != 0 && other->word != 0 && self->word == other->word;
}

// A released cell on either side makes both == and != false.
static bool KYTY_SYSV_ABI JsonObjectIteratorNotEqual(const JsonObjectIterator* self,
                                                     const JsonObjectIterator* other) {
	PRINT_NAME();

	return self->word != 0 && other->word != 0 && self->word != other->word;
}

static JsonObjectPair* KYTY_SYSV_ABI JsonObjectIteratorDereference(const JsonObjectIterator* self) {
	PRINT_NAME();

	if (self->word == 0 || (self->word & 1u) != 0) {
		// Native returns head+0x30, 0x30 or the static null object's head here; none of them is a
		// Pair.
		EXIT("JSON2_OBJECT_ITER_BOUNDARY provider=hle op=dereference branch=%s\n",
		     self->word == 0 ? "cell_released"
		                     : (self->word == JSON_OBJECT_ITERATOR_SINGULAR ? "no_node" : "end"));
	}
	return reinterpret_cast<JsonObjectPair*>(self->word);
}

static JsonObjectPair* KYTY_SYSV_ABI JsonObjectPairCtor(JsonObjectPair* self, const JsonString* key,
                                                        const JsonValue* value) {
	PRINT_NAME();

	if (self != nullptr) {
		self->key.impl =
		    (key != nullptr && key->impl != nullptr ? new std::string(*key->impl) : nullptr);
		self->owner = nullptr;
		JsonValueInit(&self->value);
		JsonValueCopy(&self->value, value);
	}
	return self;
}

static void KYTY_SYSV_ABI JsonObjectPairDtor(JsonObjectPair* self) {
	PRINT_NAME();

	const auto value_type = (self != nullptr ? self->value.type : UINT32_MAX);
	const auto key_length = (self != nullptr && self->key.impl != nullptr
	                             ? static_cast<uint64_t>(self->key.impl->size())
	                             : 0);
	if (self != nullptr) {
		JsonValueClear(&self->value);
		JsonForgetCStr(self->key.impl);
		delete self->key.impl;
		self->key.impl = nullptr;
		self->owner    = nullptr;
	}

	const auto trace = g_json_pair_trace.fetch_add(1, std::memory_order_relaxed);
	if (trace < 256) {
		LOGF("JSON2_PAIR_BOUNDARY provider=hle trace=%u op=pair_dtor key_length=%" PRIu64
		     " value_type=%u\n",
		     trace, key_length, value_type);
	}
}

// one character per callback, nothing read past the root value
static bool JsonParseScan(JsonParseRead read, void* context, std::string* text, int32_t* last) {
	char c    = 0;
	auto next = [&]() {
		c     = 0;
		*last = read(&c, context);
		return *last >= 0;
	};

	do {
		next();
	} while (c == '\t' || c == '\n' || c == '\r' || c == ' ');
	if (*last < 0) {
		return false;
	}
	text->push_back(c);

	if (c == '{' || c == '[') {
		int  depth     = 1;
		bool in_string = false;
		bool escaped   = false;
		while (depth > 0) {
			if (!next()) {
				return false;
			}
			text->push_back(c);
			if (in_string) {
				if (escaped) {
					escaped = false;
				} else if (c == '\\') {
					escaped = true;
				} else if (c == '"') {
					in_string = false;
				}
			} else if (c == '"') {
				in_string = true;
			} else if (c == '{' || c == '[') {
				depth++;
			} else if (c == '}' || c == ']') {
				depth--;
			}
		}
		return true;
	}
	if (c == '"') {
		bool escaped = false;
		for (;;) {
			if (!next()) {
				return false;
			}
			text->push_back(c);
			if (escaped) {
				escaped = false;
			} else if (c == '\\') {
				escaped = true;
			} else if (c == '"') {
				return true;
			}
		}
	}
	if (c == '-' || (c >= '0' && c <= '9')) {
		// native number loop ignores the reader result, so a number at EOF still parses
		for (;;) {
			next();
			if (!((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.' || c == 'e' ||
			      c == 'E')) {
				return true;
			}
			text->push_back(c);
		}
	}
	const char* rest = (c == 't' ? "rue" : (c == 'f' ? "alse" : (c == 'n' ? "ull" : nullptr)));
	if (rest == nullptr) {
		return false;
	}
	for (; *rest != 0; rest++) {
		if (!next() || c != *rest) {
			return false;
		}
		text->push_back(c);
	}
	return true;
}

static int32_t JsonParse(JsonValue* dst, JsonParseRead read, void* context, const char* source) {
	std::string text;
	int32_t     last = 0;
	JsonValue   parsed {};
	JsonValueInit(&parsed);
	bool ok = JsonParseScan(read, context, &text, &last);
	if (ok) {
		auto json = nlohmann::json::parse(text.data(), text.data() + text.size(), nullptr, false);
		ok        = !json.is_discarded() && JsonValueFromNlohmann(&parsed, json);
	}
	if (!ok) {
		JsonValueClear(&parsed);
		const int32_t error = (last < 0 ? last : JSON_ERROR_PARSE_INVALID_CHAR);
		const auto    trace = g_json_parse_trace.fetch_add(1, std::memory_order_relaxed);
		if (trace < 64) {
			LOGF("JSON2_PARSE_BOUNDARY provider=hle trace=%u bytes=%" PRIu64
			     " result=parse_error error=0x%08x source=%s\n",
			     trace, static_cast<uint64_t>(text.size()), static_cast<uint32_t>(error), source);
		}
		return error;
	}

	JsonValueCopy(dst, &parsed);
	JsonValueClear(&parsed);
	size_t root_count = 0;
	if (dst->type == JsonValueTypeArray) root_count = JsonArrayImpl(dst->array)->size();
	if (dst->type == JsonValueTypeObject) root_count = JsonValueObjectImpl(dst->object)->size();
	const auto trace = g_json_parse_trace.fetch_add(1, std::memory_order_relaxed);
	if (trace < 64) {
		LOGF("JSON2_PARSE_BOUNDARY provider=hle trace=%u bytes=%" PRIu64
		     " result=success root_type=%u root_count=%" PRIu64 " source=%s\n",
		     trace, static_cast<uint64_t>(text.size()), dst->type,
		     static_cast<uint64_t>(root_count), source);
	}
	return 0;
}

struct JsonParseBuffer {
	const char* pos;
	const char* end;
};

static int32_t KYTY_SYSV_ABI JsonParseBufferRead(char* out, void* context) {
	auto* buffer = static_cast<JsonParseBuffer*>(context);
	if (buffer->pos == buffer->end) {
		return JSON_ERROR_PARSE_INVALID_CHAR;
	}
	*out = *buffer->pos++;
	return 0;
}

static int32_t KYTY_SYSV_ABI JsonParserParse(JsonValue* dst, const char* src, size_t size) {
	PRINT_NAME();

	if (!g_json_initialized) {
		return JsonNotInitialized("Parser::parse(buffer)");
	}

	JsonParseBuffer buffer {src, src + size};
	return JsonParse(dst, JsonParseBufferRead, &buffer, "buffer");
}

static int32_t KYTY_SYSV_ABI JsonParserParseCallback(JsonValue* dst, JsonParseRead read,
                                                     void* context) {
	PRINT_NAME();

	if (!g_json_initialized) {
		return JsonNotInitialized("Parser::parse(callback)");
	}

	return JsonParse(dst, read, context, "callback");
}

struct JsonParseFile {
	int               fd;
	std::vector<char> buffer;
	size_t            pos;
	size_t            size;
};

static int32_t KYTY_SYSV_ABI JsonParseFileRead(char* out, void* context) {
	auto* file = static_cast<JsonParseFile*>(context);
	if (file->fd < 0) {
		return (file->fd == LibKernel::KERNEL_ERROR_ENOENT ? JSON_ERROR_NOFILE : file->fd);
	}
	if (file->pos == file->size) {
		const int64_t count =
		    LibKernel::FileSystem::KernelRead(file->fd, file->buffer.data(), file->buffer.size());
		if (count <= 0) {
			return (count == 0 ? JSON_ERROR_PARSE_INVALID_CHAR : static_cast<int32_t>(count));
		}
		file->pos  = 0;
		file->size = static_cast<size_t>(count);
	}
	*out = file->buffer[file->pos++];
	return 0;
}

static int32_t KYTY_SYSV_ABI JsonParserParseFile(JsonValue* dst, const char* path) {
	PRINT_NAME();

	LOGF("\t path = %s\n", path);

	if (!g_json_initialized) {
		return JsonNotInitialized("Parser::parse(file)");
	}
	if (g_json_file_buffer_size == 0) {
		return JSON_ERROR_NOBUF;
	}

	JsonParseFile file {};
	file.buffer.resize(g_json_file_buffer_size);
	file.fd              = LibKernel::FileSystem::KernelOpen(path, 0, 0x16D);
	const int32_t result = JsonParse(dst, JsonParseFileRead, &file, "file");
	if (file.fd >= 0) {
		LibKernel::FileSystem::KernelClose(file.fd);
	}
	return result;
}

// Both exported spellings share one slot. Stored so a second registration is refused
static int32_t KYTY_SYSV_ABI JsonInitializerSetGlobalNullAccessCallback(void* self, void* callback,
                                                                        void* context) {
	PRINT_NAME();

	int32_t result = 0;
	if (!g_json_initialized || *static_cast<uint8_t*>(self) == 0) {
		result = JSON_ERROR_NOINIT;
	} else if (callback == nullptr) {
		result = JSON_ERROR_INVALID_ARGUMENT;
	} else if (g_json_null_access_callback != nullptr) {
		result = JSON_ERROR_ALREADY_SET;
	} else {
		g_json_null_access_callback = callback;
	}

	LOGF("\t self     = 0x%016" PRIx64 "\n"
	     "\t callback = 0x%016" PRIx64 "\n"
	     "\t context  = 0x%016" PRIx64 "\n"
	     "\t result   = 0x%08x\n",
	     reinterpret_cast<uint64_t>(self), reinterpret_cast<uint64_t>(callback),
	     reinterpret_cast<uint64_t>(context), static_cast<uint32_t>(result));

	return result;
}

static int32_t KYTY_SYSV_ABI JsonInitializerSetGlobalSpecialFloatHandler(
    void* self, JsonSpecialFloatHandler handler, void* context) {
	PRINT_NAME();

	int32_t result = 0;
	if (!g_json_initialized || *static_cast<uint8_t*>(self) == 0) {
		result = JSON_ERROR_NOINIT;
	} else if (!g_json_init_parameter2) {
		result = JSON_ERROR_NOT_SUPPORTED;
	} else if (handler == nullptr) {
		result = JSON_ERROR_INVALID_ARGUMENT;
	} else if (g_json_special_float_handler != nullptr) {
		result = JSON_ERROR_ALREADY_SET;
	} else {
		g_json_special_float_handler = handler;
		g_json_special_float_context = context;
	}

	LOGF("\t self    = 0x%016" PRIx64 "\n"
	     "\t handler = 0x%016" PRIx64 "\n"
	     "\t context = 0x%016" PRIx64 "\n"
	     "\t result  = 0x%08x\n",
	     reinterpret_cast<uint64_t>(self), reinterpret_cast<uint64_t>(handler),
	     reinterpret_cast<uint64_t>(context), static_cast<uint32_t>(result));

	return result;
}

static void KYTY_SYSV_ABI JsonMemAllocatorNotifyError(void*, int32_t error, size_t size, void*) {
	PRINT_NAME();

	if (error == JSON_ERROR_NOMEM) {
		LOGF("[libSceJson] Allocation Fail. size = %" PRIu64 "\n", static_cast<uint64_t>(size));
	} else {
		LOGF("[libSceJson] unknown notification[0x%x]\n", static_cast<uint32_t>(error));
	}
}

static int32_t KYTY_SYSV_ABI JsonValueCount(const JsonValue* self) {
	PRINT_NAME();

	if (self == nullptr) {
		return 0;
	}

	switch (self->type) {
		case JsonValueTypeArray: return static_cast<int32_t>(JsonArrayImpl(self->array)->size());
		case JsonValueTypeObject: return static_cast<int32_t>(JsonValueObjectImpl(self->object)->size());
		default: return 0;
	}
}

static void KYTY_SYSV_ABI JsonValueClearMethod(void* self) {
	PRINT_NAME();

	LOGF("\t self = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(self));

	auto* value = reinterpret_cast<JsonValue*>(self);
	if (value != nullptr) {
		auto* parent    = value->parent;
		auto* rootparam = value->rootparam;
		JsonValueClear(value);
		value->parent    = parent;
		value->rootparam = rootparam;
	}
}

LIB_DEFINE(InitNet_1_Json2) {
	LIB_FUNC("-hJRce8wn1U", LibJson2::JsonMemAllocatorCtor);
	LIB_FUNC("WSOuge5IsCg", LibJson2::JsonInitParameter2Ctor);
	LIB_FUNC("GvGvswb0v34", LibJson2::JsonInitParameter2Ctor);
	LIB_FUNC("I2QC8PYhJWY", LibJson2::JsonInitParameter2SetAllocator);
	LIB_FUNC("W72B9ylU2JA", LibJson2::JsonInitParameter2SetAllocator);
	LIB_FUNC("Eu95jmqn5Rw", LibJson2::JsonInitParameter2SetFileBufferSize);
	LIB_FUNC("WVZBP4IyM+E", LibJson2::JsonInitParameter2SetSpecialFloatFormatType);
	LIB_FUNC("cK6bYHf-Q5E", LibJson2::JsonInitializerCtor);
	LIB_FUNC("IXW-z8pggfg", LibJson2::JsonInitializerInitialize);
	LIB_FUNC("Cxwy7wHq4J0", LibJson2::JsonInitializerInitializeV1);
	LIB_FUNC("PR5k1penBLM", LibJson2::JsonInitializerTerminate);
	// ~Initializer, native body is a jmp to PR5k1penBLM
	LIB_FUNC("RujUxbr3haM", LibJson2::JsonInitializerTerminate);
	LIB_FUNC("OcAgPxcq5Vk", LibJson2::JsonMemAllocatorDtor);
	LIB_FUNC("qBMjqyBn3OM", LibJson2::JsonValueCtor);
	LIB_FUNC("-wa17B7TGnw", LibJson2::JsonValueCtor);
	LIB_FUNC("fSb2oQTNrgA", LibJson2::JsonValueCopyCtor);
	LIB_FUNC("CbrT3dwDILo", LibJson2::JsonValueTypeCtor);
	LIB_FUNC("WTtYf+cNnXI", LibJson2::JsonValueDtor);
	LIB_FUNC("0eUrW9JAxM0", LibJson2::JsonValueDtor);
	LIB_FUNC("S5JxQnoGF3E", LibJson2::JsonParserParse);
	LIB_FUNC("HwDt5lD9Bfo", LibJson2::JsonValueIndexString);
	LIB_FUNC("epJ6x2LV0kU", LibJson2::JsonValueGetString);
	LIB_FUNC("L1KAkYWml-M", LibJson2::JsonStringCStr);
	LIB_FUNC("OJPTonqdg0I", LibJson2::JsonObjectCtor);
	LIB_FUNC("sZIoMRGO+jk", LibJson2::JsonValueStringCtor);
	LIB_FUNC("ERuf9y0DY84", LibJson2::JsonObjectIndex);
	LIB_FUNC("4zrm6VrgIAw", LibJson2::JsonValueAssign);
	LIB_FUNC("a+W7HHlwpBs", LibJson2::JsonObjectCopyCtor);
	LIB_FUNC("5JmzZt8twAo", LibJson2::JsonObjectDtor);
	LIB_FUNC("nM5XqdeXFPw", LibJson2::JsonValueReferArray);
	LIB_FUNC("-NxEk7XLkDY", LibJson2::JsonValueReferObject);
	LIB_FUNC("JP-PtKMiI1E", LibJson2::JsonArrayCtor);
	LIB_FUNC("HJ8GpRT1aiw", LibJson2::JsonArrayDtor);
	LIB_FUNC("iZeYfOxtMRg", LibJson2::JsonValueArrayCtor);
	LIB_FUNC("dFCphqnd+a4", LibJson2::JsonValueSetObject);
	LIB_FUNC("zQtLRTqceMY", LibJson2::JsonArrayPushBack);
	LIB_FUNC("2mbVAtshWRI", LibJson2::JsonArrayErase);
	LIB_FUNC("pPs3qZTZQvQ", LibJson2::JsonArrayPopFront);
	LIB_FUNC("bI5AGFMydrA", LibJson2::JsonArrayCopyCtor);
	LIB_FUNC("w5UbvPLGye0", LibJson2::JsonArrayAssign);
	LIB_FUNC("qVOSuDRHCpA", LibJson2::JsonArrayClear);
	LIB_FUNC("9uP25i6ipno", LibJson2::JsonArrayEmpty);
	LIB_FUNC("zcfZQyM7eAE", LibJson2::JsonArrayFront);
	LIB_FUNC("195ad-jAsTU", LibJson2::JsonValueSetArray);
	LIB_FUNC("0lLK8+kDqmE", LibJson2::JsonValueIntCtor);
	LIB_FUNC("urOpESTBZmo", LibJson2::JsonObjectAssign);
	LIB_FUNC("zTwZdI8AZ5Y", LibJson2::JsonValueGetBoolean);
	LIB_FUNC("R7FDWtcN6f8", LibJson2::JsonValueSerialize);
	LIB_FUNC("MsMOdxWfbwQ", LibJson2::JsonValueGetValue);
	LIB_FUNC("wLsJlmgEIaI", LibJson2::JsonValueReferValueKey);
	LIB_FUNC("Ncel8t2Rrpc", LibJson2::JsonValueToString);
	LIB_FUNC("oH8aBmLU+fc", LibJson2::JsonObjectClear);
	LIB_FUNC("bAM9Qwofus0", LibJson2::JsonArrayBack);
	LIB_FUNC("UeuWT+yNdCQ", LibJson2::JsonValueBoolCtor);
	LIB_FUNC("3xUXnmUkXfo", LibJson2::JsonValueObjectCtor);
	LIB_FUNC("cn9svYGWKDQ", LibJson2::JsonStringAssign);
	LIB_FUNC("b9V6fmppLXY", LibJson2::JsonValueCStringCtor);
	LIB_FUNC("EUH+EmT-v9E", LibJson2::JsonStringLength);
	LIB_FUNC("XlWbvieLj2M", LibJson2::JsonValueIndexUInt);
	LIB_FUNC("IlsmvBtMkak", LibJson2::JsonValueGetObject);
	LIB_FUNC("SHtAad20YYM", LibJson2::JsonValueGetType);
	LIB_FUNC("DIxvoy7Ngvk", LibJson2::JsonValueGetInteger);
	LIB_FUNC("qSmqLXXCPas", LibJson2::JsonStringCtor);
	LIB_FUNC("ONT8As5R1ug", LibJson2::JsonValueGetArray);
	LIB_FUNC("3qrge7L-AU4", LibJson2::JsonValueGetReal);
	LIB_FUNC("sOmU4vnx3s0", LibJson2::JsonValueDoubleCtor);
	LIB_FUNC("rQGJeNjOuUk", LibJson2::JsonArraySize);
	LIB_FUNC("bcH5EnFE2xY", LibJson2::JsonArrayBegin);
	LIB_FUNC("WXF2ihRF+B8", LibJson2::JsonArrayEnd);
	LIB_FUNC("5AZPp99ogrc", LibJson2::JsonArrayIteratorNotEqual);
	LIB_FUNC("wcgr5mte7T8", LibJson2::JsonArrayIteratorDereference);
	LIB_FUNC("w5+VCznos5E", LibJson2::JsonArrayIteratorIncrement);
	// operator++(int); the native body is byte-identical to w5+VCznos5E and would misread an HLE
	// iterator
	LIB_FUNC("GEylwSsiGG8", LibJson2::JsonArrayIteratorIncrement);
	LIB_FUNC("9yLjn46Ypfs", LibJson2::JsonArrayIteratorDtor);
	// operator->, native body identical to wcgr5mte7T8
	LIB_FUNC("iAIYn4oAWvI", LibJson2::JsonArrayIteratorDereference);
	LIB_FUNC("T3WReElX4BY", LibJson2::JsonArrayIteratorAssign);
	// every member reading the iterator cell has to agree on the HLE word, so the whole family
	// moves together
	LIB_FUNC("xhAcaIwnrgk", LibJson2::JsonObjectBegin);
	LIB_FUNC("ivMCitpSQNk", LibJson2::JsonObjectEnd);
	LIB_FUNC("ehN1Biw3tw8", LibJson2::JsonObjectFind);
	LIB_FUNC("a2Zv3idT0sU", LibJson2::JsonObjectIteratorCtor);
	LIB_FUNC("OxO+V0ouoS4", LibJson2::JsonObjectIteratorCtor);
	LIB_FUNC("JATlaeBu+lU", LibJson2::JsonObjectIteratorCopyCtor);
	LIB_FUNC("r5CShmcua+M", LibJson2::JsonObjectIteratorCopyCtor);
	LIB_FUNC("hoINmSMlYjI", LibJson2::JsonObjectIteratorDtor);
	LIB_FUNC("patTzc7zBjw", LibJson2::JsonObjectIteratorDtor);
	LIB_FUNC("w7nqTT3zgxU", LibJson2::JsonObjectIteratorAssign);
	LIB_FUNC("DlWmn2ZQuWY", LibJson2::JsonObjectIteratorIncrement);
	// operator++(int), native body identical to DlWmn2ZQuWY including the returned self
	LIB_FUNC("dIVxrrdpS9M", LibJson2::JsonObjectIteratorIncrement);
	LIB_FUNC("h-V8r4EF7bo", LibJson2::JsonObjectIteratorAdvance);
	LIB_FUNC("q3YO1c0RqFo", LibJson2::JsonObjectIteratorEqual);
	LIB_FUNC("+isUKw4zud4", LibJson2::JsonObjectIteratorNotEqual);
	LIB_FUNC("EnesV4gXDtE", LibJson2::JsonObjectIteratorDereference);
	// operator*, returns the same Pair as operator->
	LIB_FUNC("ZCd6IYoD3Bc", LibJson2::JsonObjectIteratorDereference);
	LIB_FUNC("+hYsagaV-Ug", LibJson2::JsonObjectPairCtor);
	LIB_FUNC("lt3J4dPvEtM", LibJson2::JsonObjectPairCtor);
	LIB_FUNC("Q0ng4sWj2E8", LibJson2::JsonObjectPairDtor);
	LIB_FUNC("TM0Sj+Ebins", LibJson2::JsonObjectPairDtor);
	LIB_FUNC("VbFjEs--uiA", LibJson2::JsonStringEqualCString);
	LIB_FUNC("DM43TNBBfb0", LibJson2::JsonStringEqual);
	LIB_FUNC("5yHuiWXo2gg", LibJson2::JsonValueSetBool);
	LIB_FUNC("QxVVYhP-mvg", LibJson2::JsonValueSetInt);
	LIB_FUNC("SIe1ZmW7e7s", LibJson2::JsonValueSetUInt);
	LIB_FUNC("BSmWDIkV4w4", LibJson2::JsonValueSetDouble);
	LIB_FUNC("6l3Bv2gysNc", LibJson2::JsonValueSetString);
	LIB_FUNC("9KUZFjI1IxA", LibJson2::JsonStringCStringCtor);
	LIB_FUNC("0CAesfH963Q", LibJson2::JsonStringCopyCtor);
	LIB_FUNC("gALFgNfF+9I", LibJson2::JsonStringCopyCtor);
	LIB_FUNC("cG1VE2HMl6c", LibJson2::JsonStringDtor);
	LIB_FUNC("IKQimvG9Wqs", LibJson2::JsonValueSetType);
	LIB_FUNC("RBw+4NukeGQ", LibJson2::JsonValueCount);
	LIB_FUNC("+drDFyAS6u4", LibJson2::JsonInitializerSetGlobalNullAccessCallback);
	LIB_FUNC("00oCq0RwSAY", LibJson2::JsonInitializerSetGlobalNullAccessCallback);
	LIB_FUNC("FIjXN2TkuTs", LibJson2::JsonValueClearMethod);
	// everything else: a native one would misread the HLE String/Array/Object cells
	LIB_FUNC("ol7KhQl8kfw", LibJson2::JsonObjectInsert);
	LIB_FUNC("3ZhL-MkICwI", LibJson2::JsonObjectErase);
	LIB_FUNC("fSGHm9RjN5U", LibJson2::JsonObjectSize);
	LIB_FUNC("i2l3IYvQ9UE", LibJson2::JsonObjectEmpty);
	LIB_FUNC("TAPTWYaYf8Q", LibJson2::JsonArrayIteratorCtor);
	LIB_FUNC("IaIvX3kgyb0", LibJson2::JsonArrayIteratorCopyCtor);
	LIB_FUNC("x4AUdbhpRB0", LibJson2::JsonValueUIntCtor);
	// Value::set(const Value&); operator= is this plus the returned self
	LIB_FUNC("XL8+BUqjB1w", LibJson2::JsonValueAssign);
	LIB_FUNC("a-aMMUXqrN0", LibJson2::JsonValueToBool);
	LIB_FUNC("9PqrCLfKZZI", LibJson2::JsonValueSwap);
	LIB_FUNC("l1URiQJlSoU", LibJson2::JsonValueSerializeStringCallback);
	LIB_FUNC("PyMbL9F2oBY", LibJson2::JsonValueSerializeCallback);
	LIB_FUNC("Xbl-LYVFNEE", LibJson2::JsonValueSetNullAccessCallback);
	LIB_FUNC("m5J28iw-QPs", LibJson2::JsonValueReferString);
	LIB_FUNC("gLzCc67aTbw", LibJson2::JsonValueReferValueIndex);
	LIB_FUNC("sn4HNCtNRzY", LibJson2::JsonValueGetUInteger);
	// operator[](const String&) const
	LIB_FUNC("clF7J7N9xXE", LibJson2::JsonValueGetValue);
	LIB_FUNC("itqj2YmuAa8", LibJson2::JsonParserParseCallback);
	LIB_FUNC("LB3jxppxyKU", LibJson2::JsonParserParseFile);
	// size(), same as length()
	LIB_FUNC("UVBkipSD2sw", LibJson2::JsonStringLength);
	LIB_FUNC("wM4LO2iK3s8", LibJson2::JsonStringEmpty);
	LIB_FUNC("Rz00kiTKypo", LibJson2::JsonStringAppend);
	LIB_FUNC("Va5FJ6TmNCw", LibJson2::JsonStringAppendCString);
	// operator+=(const char*), native body identical to Va5FJ6TmNCw
	LIB_FUNC("aVDQZGAqOo8", LibJson2::JsonStringAppendCString);
	LIB_FUNC("bREqDgXlqDU", LibJson2::JsonStringAppendBytes);
	LIB_FUNC("A+FhGENHV-E", LibJson2::JsonStringClear);
	LIB_FUNC("Yfw63FVJgtU", LibJson2::JsonStringCompareCString);
	LIB_FUNC("yjsf6SvXA08", LibJson2::JsonStringFindCString);
	LIB_FUNC("8OCexW9qJgQ", LibJson2::JsonStringSubstr);
	LIB_FUNC("i1393UBWu1U", LibJson2::JsonInitializerSetGlobalSpecialFloatHandler);
	LIB_FUNC("i-XwZjw0OOY", LibJson2::JsonMemAllocatorNotifyError);
}

} // namespace LibJson2

} // namespace Libs
