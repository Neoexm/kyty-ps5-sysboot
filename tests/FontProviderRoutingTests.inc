struct FontRoutingMemory {
  uint16_t type;
  uint16_t attr;
  uint32_t size;
  void* address;
  void* mspace;
  const void* memory_interface;
  void* destroy;
  void* destroy_object;
  void* user;
  void* parent;
};
