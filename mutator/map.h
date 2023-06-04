#include <xxhash.h>

#ifdef __cplusplus
extern "C"{
#endif

void* kale_map_create();

void kale_map_free(void* map);

unsigned char* kale_map_get(void* map, XXH64_hash_t hash, size_t *outSize);
void kale_map_store(void* map, XXH64_hash_t hash, unsigned char* data, size_t dataSize);

#ifdef __cplusplus
}
#endif