struct Json2ContractApi {
  using Iterator = const void *const *;
  using ValueCtor = void *(KYTY_SYSV_ABI *)(void *);
  using ValueCopyCtor = void *(KYTY_SYSV_ABI *)(void *, const void *);
  using ValueDtor = void (KYTY_SYSV_ABI *)(void *);
  using Parse = int32_t (KYTY_SYSV_ABI *)(void *, const char *, size_t);
  using IndexString = const void *(KYTY_SYSV_ABI *)(const void *, const char *);
  using IndexUInt = const void *(KYTY_SYSV_ABI *)(const void *, uint64_t);
  using GetArray = const void *(KYTY_SYSV_ABI *)(const void *);
  using ArraySize = size_t (KYTY_SYSV_ABI *)(const void *);
  using ArrayBound = Iterator *(KYTY_SYSV_ABI *)(Iterator *, const void *);
  using IteratorNotEqual = bool (KYTY_SYSV_ABI *)(const Iterator *, const Iterator *);
  using IteratorDeref = const void *(KYTY_SYSV_ABI *)(const Iterator *);
  using IteratorIncrement = Iterator *(KYTY_SYSV_ABI *)(Iterator *);
  using StringCtor = void *(KYTY_SYSV_ABI *)(void *, const char *);
  using StringCopyCtor = void *(KYTY_SYSV_ABI *)(void *, const void *);
  using StringDtor = void (KYTY_SYSV_ABI *)(void *);
  using GetValue = const void *(KYTY_SYSV_ABI *)(const void *, const void *);
  using ReferValue = const void *(KYTY_SYSV_ABI *)(void *, const void *);
  using GetType = uint32_t (KYTY_SYSV_ABI *)(const void *);
  using GetInteger = const int64_t *(KYTY_SYSV_ABI *)(const void *);
  using Count = int32_t (KYTY_SYSV_ABI *)(const void *);
  using GetObject = const void *(KYTY_SYSV_ABI *)(const void *);
  using ObjectBound = uint64_t *(KYTY_SYSV_ABI *)(uint64_t *, const void *);
  using ObjectFind = uint64_t *(KYTY_SYSV_ABI *)(uint64_t *, const void *, const void *);
  using ObjectIteratorCtor = uint64_t *(KYTY_SYSV_ABI *)(uint64_t *);
  using ObjectIteratorCopy = uint64_t *(KYTY_SYSV_ABI *)(uint64_t *, const uint64_t *);
  using ObjectIteratorDtor = void (KYTY_SYSV_ABI *)(uint64_t *);
  using ObjectIteratorAdvance = void (KYTY_SYSV_ABI *)(uint64_t *, uint64_t);
  using ObjectIteratorCompare = bool (KYTY_SYSV_ABI *)(const uint64_t *, const uint64_t *);
  using ObjectIteratorDeref = const void *(KYTY_SYSV_ABI *)(const uint64_t *);
  using ObjectPairCtor = void *(KYTY_SYSV_ABI *)(void *, const void *, const void *);
  using ObjectPairDtor = void (KYTY_SYSV_ABI *)(void *);
  using ObjectCtor = void *(KYTY_SYSV_ABI *)(void *);
  using ObjectCopy = void *(KYTY_SYSV_ABI *)(void *, const void *);
  using ObjectIndex = void *(KYTY_SYSV_ABI *)(void *, const void *);
  using ObjectRelease = void (KYTY_SYSV_ABI *)(void *);
  using CStr = const char *(KYTY_SYSV_ABI *)(const void *);

  Loader::SymbolDatabase symbols;
  ValueCtor value_ctor;
  ValueCopyCtor value_copy_ctor;
  ValueDtor value_dtor;
  Parse parse;
  IndexString index_string;
  IndexUInt index_uint;
  GetArray get_array;
  ArraySize array_size;
  ArrayBound begin;
  ArrayBound end;
  IteratorNotEqual not_equal;
  IteratorDeref deref;
  IteratorIncrement increment;
  StringCtor string_ctor;
  StringCopyCtor string_copy_ctor;
  StringDtor string_dtor;
  GetValue get_value;
  ReferValue refer_value;
  GetType get_type;
  GetInteger get_integer;
  Count count;
  GetObject get_object;
  GetObject get_string;
  CStr c_str;
  ObjectBound object_begin;
  ObjectBound object_end;
  ObjectFind object_find;
  ObjectIteratorCtor object_iterator_ctor;
  ObjectIteratorCopy object_iterator_copy;
  ObjectIteratorDtor object_iterator_dtor;
  ObjectIteratorCopy object_iterator_assign;
  ObjectIteratorCtor object_increment;
  ObjectIteratorCtor object_post_increment;
  ObjectIteratorAdvance object_advance;
  ObjectIteratorCompare object_equal;
  ObjectIteratorCompare object_not_equal;
  ObjectIteratorDeref object_arrow;
  ObjectIteratorDeref object_star;
  ObjectPairCtor object_pair_ctor;
  ObjectPairDtor object_pair_dtor;
  ObjectCtor object_ctor;
  ObjectCopy object_copy;
  ObjectRelease object_dtor;
  ObjectIndex object_index;
  ObjectRelease object_clear;
  ObjectCopy array_copy;
  ObjectRelease array_dtor;

  Json2ContractApi() {
    Libs::LibJson2::InitNet_1_Json2(&symbols);
    const auto find = [&](const char *nid) {
      const auto *symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
      Check(symbol != nullptr, "Json2 ResourceArbitrator export resolves");
      return symbol->vaddr;
    };
    value_ctor = reinterpret_cast<ValueCtor>(find("qBMjqyBn3OM"));
    value_copy_ctor = reinterpret_cast<ValueCopyCtor>(find("fSb2oQTNrgA"));
    value_dtor = reinterpret_cast<ValueDtor>(find("WTtYf+cNnXI"));
    parse = reinterpret_cast<Parse>(find("S5JxQnoGF3E"));
    index_string = reinterpret_cast<IndexString>(find("HwDt5lD9Bfo"));
    index_uint = reinterpret_cast<IndexUInt>(find("XlWbvieLj2M"));
    get_array = reinterpret_cast<GetArray>(find("ONT8As5R1ug"));
    array_size = reinterpret_cast<ArraySize>(find("rQGJeNjOuUk"));
    begin = reinterpret_cast<ArrayBound>(find("bcH5EnFE2xY"));
    end = reinterpret_cast<ArrayBound>(find("WXF2ihRF+B8"));
    not_equal = reinterpret_cast<IteratorNotEqual>(find("5AZPp99ogrc"));
    deref = reinterpret_cast<IteratorDeref>(find("wcgr5mte7T8"));
    increment = reinterpret_cast<IteratorIncrement>(find("w5+VCznos5E"));
    string_ctor = reinterpret_cast<StringCtor>(find("9KUZFjI1IxA"));
    string_copy_ctor = reinterpret_cast<StringCopyCtor>(find("0CAesfH963Q"));
    string_dtor = reinterpret_cast<StringDtor>(find("cG1VE2HMl6c"));
    get_value = reinterpret_cast<GetValue>(find("MsMOdxWfbwQ"));
    refer_value = reinterpret_cast<ReferValue>(find("wLsJlmgEIaI"));
    get_type = reinterpret_cast<GetType>(find("SHtAad20YYM"));
    get_integer = reinterpret_cast<GetInteger>(find("DIxvoy7Ngvk"));
    count = reinterpret_cast<Count>(find("RBw+4NukeGQ"));
    get_object = reinterpret_cast<GetObject>(find("IlsmvBtMkak"));
    get_string = reinterpret_cast<GetObject>(find("epJ6x2LV0kU"));
    c_str = reinterpret_cast<CStr>(find("L1KAkYWml-M"));
    object_begin = reinterpret_cast<ObjectBound>(find("xhAcaIwnrgk"));
    object_end = reinterpret_cast<ObjectBound>(find("ivMCitpSQNk"));
    object_find = reinterpret_cast<ObjectFind>(find("ehN1Biw3tw8"));
    object_iterator_ctor = reinterpret_cast<ObjectIteratorCtor>(find("a2Zv3idT0sU"));
    object_iterator_copy = reinterpret_cast<ObjectIteratorCopy>(find("JATlaeBu+lU"));
    object_iterator_dtor = reinterpret_cast<ObjectIteratorDtor>(find("hoINmSMlYjI"));
    object_iterator_assign = reinterpret_cast<ObjectIteratorCopy>(find("w7nqTT3zgxU"));
    object_increment = reinterpret_cast<ObjectIteratorCtor>(find("DlWmn2ZQuWY"));
    object_post_increment = reinterpret_cast<ObjectIteratorCtor>(find("dIVxrrdpS9M"));
    object_advance = reinterpret_cast<ObjectIteratorAdvance>(find("h-V8r4EF7bo"));
    object_equal = reinterpret_cast<ObjectIteratorCompare>(find("q3YO1c0RqFo"));
    object_not_equal = reinterpret_cast<ObjectIteratorCompare>(find("+isUKw4zud4"));
    object_arrow = reinterpret_cast<ObjectIteratorDeref>(find("EnesV4gXDtE"));
    object_star = reinterpret_cast<ObjectIteratorDeref>(find("ZCd6IYoD3Bc"));
    object_pair_ctor = reinterpret_cast<ObjectPairCtor>(find("+hYsagaV-Ug"));
    object_pair_dtor = reinterpret_cast<ObjectPairDtor>(find("Q0ng4sWj2E8"));
    object_ctor = reinterpret_cast<ObjectCtor>(find("OJPTonqdg0I"));
    object_copy = reinterpret_cast<ObjectCopy>(find("a+W7HHlwpBs"));
    object_dtor = reinterpret_cast<ObjectRelease>(find("5JmzZt8twAo"));
    object_index = reinterpret_cast<ObjectIndex>(find("ERuf9y0DY84"));
    object_clear = reinterpret_cast<ObjectRelease>(find("oH8aBmLU+fc"));
    array_copy = reinterpret_cast<ObjectCopy>(find("bI5AGFMydrA"));
    array_dtor = reinterpret_cast<ObjectRelease>(find("HJ8GpRT1aiw"));
    Check(find("OxO+V0ouoS4") == reinterpret_cast<uint64_t>(object_iterator_ctor) &&
              find("r5CShmcua+M") == reinterpret_cast<uint64_t>(object_iterator_copy) &&
              find("patTzc7zBjw") == reinterpret_cast<uint64_t>(object_iterator_dtor) &&
              find("gALFgNfF+9I") == reinterpret_cast<uint64_t>(string_copy_ctor) &&
              find("lt3J4dPvEtM") == reinterpret_cast<uint64_t>(object_pair_ctor) &&
              find("TM0Sj+Ebins") == reinterpret_cast<uint64_t>(object_pair_dtor),
          "Json2 C2/D2 aliases resolve to the HLE C1/D1 bodies");
  }
};

std::vector<uint64_t> Json2ReferenceIds(const std::string &bytes) {
  const auto json = nlohmann::json::parse(bytes, nullptr, false);
  Check(!json.is_discarded() && json.is_object(), "parse reference ResourceArbitrator JSON bytes");
  const auto found = json.find("clientComponents");
  Check(found != json.end() && found->is_array(), "reference ResourceArbitrator clientComponents array");
  std::vector<uint64_t> ids;
  ids.reserve(found->size());
  for (const auto &component : *found) {
    Check(component.is_object() && component.contains("id") && component.at("id").is_number_integer(),
          "reference ResourceArbitrator component has an integer id");
    const auto id = component.at("id").get<int64_t>();
    Check(id >= 0, "reference ResourceArbitrator id is unsigned-compatible");
    ids.push_back(static_cast<uint64_t>(id));
  }
  return ids;
}

const void *CheckJson2ClientComponents(Json2ContractApi &api, const void *root,
                                       const std::vector<uint64_t> &expected,
                                       const void **first_id_out = nullptr) {
  const void *components = api.index_string(root, "clientComponents");
  Check(components != nullptr && api.get_type(components) == 6,
        "parsed ResourceArbitrator clientComponents is an array Value");
  const void *array = api.get_array(components);
  Check(array != nullptr && api.array_size(array) == expected.size(),
        "parsed ResourceArbitrator component count matches bytes");

  alignas(8) unsigned char id_key[8] {};
  api.string_ctor(id_key, "id");
  Json2ContractApi::Iterator it = nullptr;
  Json2ContractApi::Iterator last = nullptr;
  api.begin(&it, array);
  api.end(&last, array);
  const void *first = nullptr;
  size_t index = 0;
  while (api.not_equal(&it, &last)) {
    Check(index < expected.size(), "Json2 iterator stays within the parsed component count");
    const void *component = api.deref(&it);
    if (index == 0) first = component;
    Check(component != nullptr && api.get_type(component) == 7,
          "parsed ResourceArbitrator component is an object Value");
    const int32_t before_count = api.count(component);
    const void *id = api.get_value(component, id_key);
    Check(id != nullptr && (api.get_type(id) == 2 || api.get_type(id) == 3),
          "Value::getValue returns the parsed id Value");
    Check(api.get_value(component, id_key) == id &&
              api.refer_value(const_cast<void *>(component), id_key) == id,
          "Value::getValue returns the existing borrowed child without a copy");
    if (index == 0 && first_id_out != nullptr) *first_id_out = id;
    uint64_t raw_value = 0;
    uint32_t raw_type = 0;
    std::memcpy(&raw_value, static_cast<const unsigned char *>(id) + 16, sizeof(raw_value));
    std::memcpy(&raw_type, static_cast<const unsigned char *>(id) + 28, sizeof(raw_type));
    Check(raw_type == api.get_type(id) && raw_value == expected[index] &&
              static_cast<uint64_t>(*api.get_integer(id)) == expected[index],
          "parsed id matches native getUInteger type and payload offsets");
    Check(api.count(component) == before_count, "Value::getValue does not create or mutate a key");
    api.increment(&it);
    index++;
  }
  Check(index == expected.size() && !api.not_equal(&it, &last),
        "Json2 iteration stops exactly at the parsed array boundary");
  api.string_dtor(id_key);
  return first;
}

std::vector<std::pair<std::string, std::string>> Json2ReferenceGroupObjects(const std::string &bytes,
                                                                            std::vector<std::string> *strings = nullptr) {
  const auto json = nlohmann::json::parse(bytes, nullptr, false);
  Check(!json.is_discarded() && json.contains("exclusiveGroups") && json.at("exclusiveGroups").is_array(),
        "reference ResourceArbitrator exclusiveGroups array");
  std::vector<std::pair<std::string, std::string>> objects;
  for (const auto &group : json.at("exclusiveGroups")) {
    for (const auto &entry : group.at("group")) {
      if (!entry.is_object()) {
        Check(entry.is_string(), "reference exclusive group entry is a string or an object");
        if (strings != nullptr) strings->push_back(entry.get<std::string>());
        continue;
      }
      Check(entry.size() == 1 && entry.begin().value().is_string(),
            "reference exclusive group object has exactly one string member");
      objects.emplace_back(entry.begin().key(), entry.begin().value().get<std::string>());
    }
  }
  return objects;
}

// Mirrors SceShellCore 0x857a40 (bI5AGFMydrA at 0x857ad2/0x857b9b, HJ8GpRT1aiw at 0x857b48): strings via getString/c_str; objects with a fresh begin per read, -> without an empty check, key via String::c_str, value via Pair+0x10 getString, iterator destroyed between the two reads.
void CheckJson2ExclusiveGroupObjects(Json2ContractApi &api, const void *root,
                                     const std::vector<std::pair<std::string, std::string>> &expected,
                                     const std::vector<std::string> &strings) {
  alignas(8) unsigned char groups[8] {};
  api.array_copy(groups, api.get_array(api.index_string(root, "exclusiveGroups")));
  Json2ContractApi::Iterator group = nullptr;
  Json2ContractApi::Iterator groups_end = nullptr;
  size_t found = 0;
  size_t found_strings = 0;
  api.begin(&group, groups);
  api.end(&groups_end, groups);
  for (; api.not_equal(&group, &groups_end); api.increment(&group)) {
    alignas(8) unsigned char members[8] {};
    api.array_copy(members, api.get_array(api.index_string(api.deref(&group), "group")));
    Json2ContractApi::Iterator member = nullptr;
    Json2ContractApi::Iterator members_end = nullptr;
    api.begin(&member, members);
    api.end(&members_end, members);
    for (; api.not_equal(&member, &members_end); api.increment(&member)) {
      const void *entry = api.deref(&member);
      if (api.get_type(entry) != 7) {
        Check(found_strings < strings.size() && strings[found_strings] == api.c_str(api.get_string(entry)),
              "a copied exclusive group string entry reads back through getString");
        found_strings++;
        continue;
      }
      Check(found < expected.size(), "exclusive group object count stays within the bytes");

      uint64_t it = 0xccccccccccccccccULL;
      Check(api.object_begin(&it, api.get_object(entry)) == &it, "Object::begin returns its result slot");
      const std::string key = api.c_str(api.object_arrow(&it));
      api.object_iterator_dtor(&it);
      Check(it == 0, "Object::iterator dtor releases the cell like native");

      it = 0xccccccccccccccccULL;
      api.object_begin(&it, api.get_object(entry));
      const void *value = static_cast<const unsigned char *>(api.object_arrow(&it)) + 16;
      const std::string text = api.c_str(api.get_string(value));
      api.object_iterator_dtor(&it);
      Check(key == expected[found].first && text == expected[found].second,
            "Object::iterator-> yields the exclusive group key and string value");

      alignas(8) unsigned char key_string[8] {};
      api.string_ctor(key_string, key.c_str());
      Check(api.get_value(entry, key_string) == value && api.get_type(value) == 5,
            "the iterator Pair value is the same borrowed child getValue returns");
      api.string_dtor(key_string);

      uint64_t first = 0;
      uint64_t last = 0;
      api.object_begin(&first, api.get_object(entry));
      api.object_end(&last, api.get_object(entry));
      Check(api.object_not_equal(&first, &last) && api.object_increment(&first) == &first &&
                api.object_equal(&first, &last),
            "a one-member object reaches end after one increment");
      api.object_iterator_dtor(&first);
      api.object_iterator_dtor(&last);
      found++;
    }
    api.array_dtor(members);
  }
  api.array_dtor(groups);
  Check(found == expected.size() && found_strings == strings.size(),
        "every exclusive group entry was visited through the Array copies");
}

void CheckJson2ObjectIteratorFamily(Json2ContractApi &api) {
  alignas(8) unsigned char root[32] {};
  constexpr char doc[] = "{\"b\":1,\"a\":\"x\",\"c\":{},\"d\":[]}";
  api.value_ctor(root);
  Check(api.parse(root, doc, sizeof(doc) - 1) == 0, "parser accepts the Object iterator edge fixture");
  const void *object = api.get_object(root);

  uint64_t it = 0;
  uint64_t last = 0;
  api.object_begin(&it, object);
  api.object_end(&last, object);
  std::string keys;
  while (api.object_not_equal(&it, &last)) {
    Check(keys.size() < 4, "Object iteration stays within the fixture member count");
    keys += api.c_str(api.object_arrow(&it));
    Check(api.object_star(&it) == api.object_arrow(&it), "Object::iterator operator* and operator-> return one Pair");
    Check(api.object_post_increment(&it) == &it, "Object::iterator operator++(int) returns self like the native body");
  }
  Check(keys == "abcd" && api.object_equal(&it, &last) && !api.object_not_equal(&it, &last),
        "Object iteration visits keys in strcmp order and stops at end");

  uint64_t walked = 0;
  api.object_begin(&walked, object);
  api.object_advance(&walked, 0);
  Check(std::string(api.c_str(api.object_arrow(&walked))) == "a", "Object::iterator advance(0) is a no-op");
  api.object_advance(&walked, 2);
  Check(std::string(api.c_str(api.object_arrow(&walked))) == "c", "Object::iterator advance(n) steps n members");

  alignas(8) unsigned char key_b[8] {};
  alignas(8) unsigned char key_missing[8] {};
  alignas(8) unsigned char key_unset[8] {};
  api.string_ctor(key_b, "b");
  api.string_ctor(key_missing, "zz");
  uint64_t hit = 0;
  uint64_t miss = 0;
  uint64_t unset = 0;
  api.object_find(&hit, object, key_b);
  Check(std::string(api.c_str(api.object_arrow(&hit))) == "b" &&
            static_cast<const unsigned char *>(api.object_arrow(&hit)) + 16 == api.get_value(root, key_b),
        "Object::find hit returns the borrowed Pair");
  api.object_find(&miss, object, key_missing);
  Check(api.object_equal(&miss, &last), "Object::find miss returns end");
  alignas(8) unsigned char key_empty[8] {};
  api.string_ctor(key_empty, "");
  miss = 0;
  api.object_find(&miss, object, key_empty);
  Check(api.object_equal(&miss, &last), "Object::find with an explicit empty key is a lookup that misses");
  api.object_find(&unset, object, key_unset);

  uint64_t singular = 0xccccccccccccccccULL;
  api.object_iterator_ctor(&singular);
  Check(api.object_equal(&unset, &singular) && api.object_not_equal(&singular, &last) &&
            !api.object_equal(&singular, &last),
        "Object::find with an unset String is the node-less iterator a default ctor makes");
  api.object_increment(&singular);
  api.object_advance(&singular, 3);
  Check(api.object_equal(&unset, &singular), "incrementing a node-less Object::iterator is a no-op");
  uint64_t singular_copy = 0xccccccccccccccccULL;
  api.object_iterator_copy(&singular_copy, &singular);
  Check(api.object_equal(&singular_copy, &unset) && api.object_not_equal(&singular_copy, &last),
        "Object::iterator copy of a node-less source stays node-less");

  uint64_t released = 0;
  uint64_t released_copy = 0xccccccccccccccccULL;
  Check(!api.object_equal(&released, &released) && !api.object_not_equal(&released, &last) &&
            !api.object_equal(&last, &released) && !api.object_not_equal(&last, &released),
        "a released Object::iterator is neither equal nor unequal to anything");
  api.object_increment(&released);
  api.object_advance(&released, 2);
  api.object_iterator_assign(&released, &last);
  api.object_iterator_copy(&released_copy, &released);
  Check(released == 0 && released_copy == 0, "a released Object::iterator stays released through ++, advance, = and copy");

  uint64_t target = 0;
  api.object_iterator_copy(&target, &last);
  Check(api.object_equal(&target, &last), "Object::iterator copy ctor keeps the position");
  api.object_iterator_assign(&target, &hit);
  Check(std::string(api.c_str(api.object_arrow(&target))) == "b", "Object::iterator= copies a positioned source");
  Check(api.object_iterator_assign(&target, &singular) == &target && target == 0,
        "Object::iterator= from a node-less source releases the destination like native");
  api.object_iterator_copy(&target, &hit);
  Check(api.object_iterator_assign(&target, &released) == &target && target == 0,
        "Object::iterator= from a released source releases a positioned destination like native");

  uint64_t empty_first = 0;
  uint64_t empty_last = 0;
  alignas(8) unsigned char key_c[8] {};
  api.string_ctor(key_c, "c");
  const void *empty = api.get_object(api.get_value(root, key_c));
  api.object_begin(&empty_first, empty);
  api.object_end(&empty_last, empty);
  Check(api.object_equal(&empty_first, &empty_last), "an empty Object has begin == end");
  const void *wrong = api.get_object(api.get_value(root, key_b));
  api.object_begin(&empty_first, wrong);
  api.object_end(&empty_last, wrong);
  Check(api.object_equal(&empty_first, &empty_last), "getObject on a non-object Value iterates as empty");
  api.object_find(&miss, wrong, key_b);
  Check(api.object_equal(&miss, &empty_last), "Object::find on the static object of a non-object Value returns its end");

  alignas(8) unsigned char owned[8] {};
  alignas(8) unsigned char owned_copy[8] {};
  alignas(8) unsigned char key_k[8] {};
  alignas(8) unsigned char key_m[8] {};
  api.string_ctor(key_k, "k");
  api.string_ctor(key_m, "m");
  api.object_ctor(owned);
  const void *created = api.object_index(owned, key_k);
  api.object_index(owned, key_m);
  uint64_t owned_it = 0;
  api.object_begin(&owned_it, owned);
  Check(std::string(api.c_str(api.object_arrow(&owned_it))) == "k" &&
            static_cast<const unsigned char *>(api.object_arrow(&owned_it)) + 16 == created,
        "Object::operator[] creates the Pair an iterator reaches");
  api.object_copy(owned_copy, owned);
  api.object_dtor(owned);
  api.object_begin(&owned_it, owned);
  Check(api.object_equal(&owned_it, &singular), "begin on a destroyed Object is node-less like native");
  api.object_begin(&owned_it, owned_copy);
  Check(std::string(api.c_str(api.object_arrow(&owned_it))) == "k" &&
            static_cast<const unsigned char *>(api.object_arrow(&owned_it)) + 16 != created,
        "an Object copy owns distinct Pairs that survive the source");
  api.object_end(&empty_last, owned_copy);
  Check(api.object_increment(&owned_it) == &owned_it && std::string(api.c_str(api.object_arrow(&owned_it))) == "m" &&
            api.object_increment(&owned_it) == &owned_it && api.object_equal(&owned_it, &empty_last),
        "an Object copy steps through its own Pairs to end after the source is destroyed");
  api.object_clear(owned_copy);
  api.object_begin(&owned_it, owned_copy);
  api.object_end(&empty_last, owned_copy);
  Check(api.object_equal(&owned_it, &empty_last), "Object::clear leaves begin == end");
  api.object_dtor(owned_copy);

  for (auto *word : {&it, &last, &walked, &hit, &miss, &unset, &singular, &singular_copy, &target, &empty_first, &empty_last, &owned_it}) {
    api.object_iterator_dtor(word);
  }
  api.string_dtor(key_b);
  api.string_dtor(key_missing);
  api.string_dtor(key_empty);
  api.string_dtor(key_c);
  api.string_dtor(key_k);
  api.string_dtor(key_m);

  alignas(8) unsigned char root_copy[32] {};
  api.value_copy_ctor(root_copy, root);
  api.value_dtor(root);
  keys.clear();
  api.object_begin(&it, api.get_object(root_copy));
  api.object_end(&last, api.get_object(root_copy));
  for (; api.object_not_equal(&it, &last); api.object_increment(&it)) {
    Check(keys.size() < 4, "Value copy iteration stays within the fixture member count");
    keys += api.c_str(api.object_arrow(&it));
  }
  Check(keys == "abcd" && api.object_equal(&it, &last), "a Value copy walks its own Pairs to end after the source is destroyed");
  api.object_iterator_dtor(&it);
  api.object_iterator_dtor(&last);
  api.value_dtor(root_copy);
}

void CheckJson2ObjectPairLifetime(Json2ContractApi &api) {
  alignas(8) unsigned char root[32] {};
  constexpr char doc[] = "{\"nested\":{\"id\":7,\"items\":[{\"x\":1}]},\"scalar\":11}";
  api.value_ctor(root);
  Check(api.parse(root, doc, sizeof(doc) - 1) == 0, "parser accepts the Object::Pair lifetime fixture");

  uint64_t it = 0;
  api.object_begin(&it, api.get_object(root));
  const auto *source = static_cast<const unsigned char *>(api.object_arrow(&it));
  Check(std::string(api.c_str(source)) == "nested" && api.get_type(source + 16) == 7,
        "Object::iterator reaches the nested HLE Pair used by the caller");

  alignas(8) unsigned char local[0x30] {};
  api.string_copy_ctor(local, source);
  std::memcpy(local + 8, source + 8, sizeof(uint32_t));
  api.value_copy_ctor(local + 16, source + 16);
  Check(std::string(api.c_str(local)) == "nested" && api.get_type(local + 16) == 7 &&
            *api.get_integer(api.index_string(local + 16, "id")) == 7 &&
            api.get_type(api.index_string(local + 16, "items")) == 6,
        "the reached inlined Pair copy keeps its HLE key and recursively copied Value");
  api.object_pair_dtor(local);
  Check(std::string(api.c_str(source)) == "nested" && api.get_type(source + 16) == 7 &&
            *api.get_integer(api.index_string(source + 16, "id")) == 7,
        "destroying the local Pair leaves its borrowed source Pair intact");

  alignas(8) unsigned char key[8] {};
  alignas(8) unsigned char pair[0x30] {};
  const std::string long_key = "pair-copy-key-longer-than-small-string-storage";
  api.string_ctor(key, long_key.c_str());
  api.object_pair_ctor(pair, key, source + 16);
  api.string_dtor(key);
  Check(std::string(api.c_str(pair)) == long_key && api.get_type(pair + 16) == 7 &&
            *api.get_integer(api.index_string(pair + 16, "id")) == 7,
        "Object::Pair construction owns independent long-key and nested-Value copies");
  api.object_pair_dtor(pair);

  alignas(8) unsigned char unset[8] {};
  alignas(8) unsigned char unset_copy[8] {};
  api.string_copy_ctor(unset_copy, unset);
  Check(std::string(api.c_str(unset_copy)).empty(), "String copy preserves an unset source as empty through const access");
  api.string_dtor(unset_copy);

  alignas(8) unsigned char long_string[8] {};
  alignas(8) unsigned char long_string_copy[8] {};
  api.string_ctor(long_string, long_key.c_str());
  api.string_copy_ctor(long_string_copy, long_string);
  api.string_dtor(long_string);
  Check(std::string(api.c_str(long_string_copy)) == long_key, "String copy owns long storage after source destruction");
  api.string_dtor(long_string_copy);

  Check(std::string(api.c_str(source)) == "nested" && api.get_type(source + 16) == 7,
        "all local Pair and String teardown paths preserve the map-owned source");
  api.object_iterator_dtor(&it);
  api.value_dtor(root);
}

// Native ++ at end reaches the getnext assert and aborts; the HLE dereference exits where native returns a non-Pair pointer.
int RunJson2ObjectIteratorExitChild(const std::string &branch) {
  Json2ContractApi api;
  alignas(8) unsigned char root[32] {};
  constexpr char doc[] = "{\"a\":1}";
  api.value_ctor(root);
  Check(api.parse(root, doc, sizeof(doc) - 1) == 0, "parser accepts the Object iterator exit fixture");
  uint64_t it = 0;
  api.object_end(&it, api.get_object(root));
  if (branch == "increment_end") api.object_increment(&it);
  if (branch == "post_increment_end") api.object_post_increment(&it);
  if (branch == "advance_end") api.object_advance(&it, 1);
  if (branch == "dereference_end") api.object_arrow(&it);
  if (branch == "dereference_no_node") api.object_star(api.object_iterator_ctor(&it));
  if (branch == "dereference_released") {
    api.object_iterator_dtor(&it);
    api.object_arrow(&it);
  }
  return 2;
}

void CheckJson2ObjectIteratorExits() {
#if defined(_WIN32)
  std::wstring executable(32768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
  Check(length > 0 && length < executable.size(), "locate the Object iterator exit child executable");
  executable.resize(length);
  TempDirectory temporary;
  const std::pair<std::string, const char *> cases[] = {
      {"increment_end", "op=increment branch=end native_assert=getnext_nil"},
      {"post_increment_end", "op=increment branch=end native_assert=getnext_nil"},
      {"advance_end", "op=increment branch=end native_assert=getnext_nil"},
      {"dereference_end", "op=dereference branch=end"},
      {"dereference_no_node", "op=dereference branch=no_node"},
      {"dereference_released", "op=dereference branch=cell_released"},
  };
  for (const auto &[branch, expected] : cases) {
    const auto log = temporary.Path() / (branch + ".log");
    auto command = L"\"" + executable + L"\" --json2-object-iterator-exit-child " +
        std::wstring(branch.begin(), branch.end()) + L" \"" + log.native() + L"\"";
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process {};
    Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process),
          "start an isolated Object iterator exit child");
    const auto wait = WaitForSingleObject(process.hProcess, 10000);
    if (wait != WAIT_OBJECT_0) {
      TerminateProcess(process.hProcess, 126);
      WaitForSingleObject(process.hProcess, 1000);
    }
    DWORD exit_code = 0xffffffffu;
    const bool status_read = GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    std::ifstream input(log, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    Check(wait == WAIT_OBJECT_0 && status_read && exit_code == 321 && text.find(expected) != std::string::npos,
          "Object::iterator boundary misuse stops on the exact HLE fatal branch");
  }
#endif
}

void RunJson2ResourceArbitratorContract(const std::string &bytes,
                                        const std::vector<uint64_t> &expected) {
  Json2ContractApi api;
  alignas(8) unsigned char root[32] {};
  alignas(8) unsigned char copy[32] {};
  api.value_ctor(root);
  Check(api.parse(root, bytes.data(), bytes.size()) == 0,
        "HLE parser accepts the ResourceArbitrator fixture bytes");
  const void *first_id = nullptr;
  const void *first = CheckJson2ClientComponents(api, root, expected, &first_id);
  std::vector<std::string> group_strings;
  const auto group_objects = Json2ReferenceGroupObjects(bytes, &group_strings);
  CheckJson2ExclusiveGroupObjects(api, root, group_objects, group_strings);
  CheckJson2ObjectIteratorFamily(api);
  CheckJson2ObjectPairLifetime(api);

  alignas(8) unsigned char missing_key[8] {};
  alignas(8) unsigned char id_key[8] {};
  alignas(8) unsigned char unset_key[8] {};
  api.string_ctor(missing_key, "notPresent");
  api.string_ctor(id_key, "id");
  const int32_t before_count = api.count(first);
  const void *missing = api.get_value(first, missing_key);
  Check(missing != nullptr && api.get_type(missing) == 0 && api.get_value(first, missing_key) == missing &&
            api.count(first) == before_count,
        "missing lookup returns one stable non-null Null Value without insertion");
  Check(api.get_value(api.index_string(root, "clientComponents"), id_key) == missing,
        "wrong parent type returns the same non-null Null Value");
  Check(api.get_value(first, unset_key) == missing,
        "unset Json2 String does not become an empty key");
  const void *components = api.index_string(root, "clientComponents");
  Check(api.index_uint(components, expected.size()) == missing,
        "out-of-range component index returns the bounded Null Value");
  api.string_dtor(missing_key);
  api.string_dtor(id_key);

  api.value_copy_ctor(copy, root);
  const void *copy_first = api.index_uint(api.index_string(copy, "clientComponents"), 0);
  alignas(8) unsigned char copy_id_key[8] {};
  api.string_ctor(copy_id_key, "id");
  const void *copy_first_id = api.get_value(copy_first, copy_id_key);
  Check(copy_first != nullptr && copy_first != first && copy_first_id != nullptr &&
            copy_first_id != first_id,
        "Value copy owns a distinct component tree");
  api.string_dtor(copy_id_key);
  api.value_dtor(root);
  CheckJson2ClientComponents(api, copy, expected);
  CheckJson2ExclusiveGroupObjects(api, copy, group_objects, group_strings);

  constexpr char malformed[] = "{\"clientComponents\":[";
  Check(static_cast<uint32_t>(api.parse(copy, malformed, sizeof(malformed) - 1)) == 0x80848101 &&
            api.array_size(api.get_array(api.index_string(copy, "clientComponents"))) == expected.size(),
        "parse failure returns the error and preserves the existing tree");
  constexpr char replacement[] = "{\"clientComponents\":[{\"id\":4294967295}]}";
  Check(api.parse(copy, replacement, sizeof(replacement) - 1) == 0,
        "parser can replace and release an existing owned tree");
  CheckJson2ClientComponents(api, copy, std::vector<uint64_t> {4294967295ULL});
  api.value_dtor(copy);

  alignas(8) unsigned char edge_root[32] {};
  alignas(8) unsigned char empty_key[8] {};
  alignas(8) unsigned char edge_id_key[8] {};
  alignas(8) unsigned char edge_unset_key[8] {};
  constexpr char edge[] = "{\"clientComponents\":[{\"\":999,\"id\":\"wrong-type\"}]}";
  api.value_ctor(edge_root);
  Check(api.parse(edge_root, edge, sizeof(edge) - 1) == 0,
        "parser accepts missing-key and wrong-value-type edge fixture");
  const void *edge_component = api.index_uint(api.index_string(edge_root, "clientComponents"), 0);
  api.string_ctor(empty_key, "");
  api.string_ctor(edge_id_key, "id");
  const void *empty_value = api.get_value(edge_component, empty_key);
  Check(empty_value != nullptr && api.get_type(empty_value) == 3 &&
            static_cast<uint64_t>(*api.get_integer(empty_value)) == 999,
        "explicit empty key remains a lookup");
  uint64_t empty_hit = 0;
  uint64_t edge_last = 0;
  api.object_find(&empty_hit, api.get_object(edge_component), empty_key);
  api.object_end(&edge_last, api.get_object(edge_component));
  Check(api.object_not_equal(&empty_hit, &edge_last) && std::string(api.c_str(api.object_arrow(&empty_hit))).empty() &&
            static_cast<const unsigned char *>(api.object_arrow(&empty_hit)) + 16 == empty_value,
        "Object::find with an explicit empty key hits the empty member");
  api.object_iterator_dtor(&empty_hit);
  api.object_iterator_dtor(&edge_last);
  Check(api.get_value(edge_component, edge_unset_key) == missing,
        "unset key remains distinct from an explicit empty key");
  const void *wrong_type = api.get_value(edge_component, edge_id_key);
  Check(wrong_type != nullptr && wrong_type != missing && api.get_type(wrong_type) == 5,
        "existing wrong-type id is returned unchanged instead of becoming zero");
  api.string_dtor(empty_key);
  api.string_dtor(edge_id_key);
  api.value_dtor(edge_root);
}

void TestJson2ResourceArbitratorDerived() {
  const std::string bytes =
      "{\"clientComponents\":[{\"id\":0},{\"id\":1},{\"id\":260}],"
      "\"exclusiveGroups\":[{\"group\":[\"A\",{\"Media App\":\"RUNNING\"}],\"coexistence\":0},"
      "{\"group\":[{\"ScreenShare\":\"RUNNING_DECODER_ONLY\"},\"B\"],\"coexistence\":1}]}";
  RunJson2ResourceArbitratorContract(bytes, Json2ReferenceIds(bytes));
  CheckJson2ObjectIteratorExits();
}

void TestJson2ResourceArbitratorOriginal(const std::filesystem::path &path,
                                         const std::string &sha256) {
  std::ifstream input(path, std::ios::binary);
  Check(input.is_open(), "open ResourceArbitrator configuration fixture");
  const std::string bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  Libs::LibKernel::AuthInfo::Digest expected {};
  Check(Libs::LibKernel::AuthInfo::ParseDigestHex(sha256, &expected) &&
            Libs::LibKernel::AuthInfo::Sha256(bytes.data(), bytes.size()) == expected,
        "ResourceArbitrator configuration hash matches the admitted fixture");
  Check(bytes.size() == 10333, "ResourceArbitrator configuration size matches the admitted fixture");
  const auto ids = Json2ReferenceIds(bytes);
  Check(ids == std::vector<uint64_t>({0, 1, 10, 11, 12, 13, 14, 100, 110, 120, 130, 140, 150, 160,
                                      165, 167, 170, 175, 177, 180, 182, 185, 260, 190, 200, 205, 220, 230,
                                      235, 240, 245, 250}),
        "all 32 expected ids are derived from the admitted bytes");
  const auto objects = Json2ReferenceGroupObjects(bytes);
  Check(objects.size() == 3 && objects[0].first.size() == 9 && objects[1].first.size() == 11 &&
            objects[2].first.size() == 11,
        "the admitted bytes carry exactly the three one-member exclusive group objects");
  RunJson2ResourceArbitratorContract(bytes, ids);
}
