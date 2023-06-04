#include "map.h"

#include <unordered_map>
#include <vector>
#include <stdlib.h>
#include <string.h>

// This is probably very badly made, but I just wanted a working map API

typedef std::unordered_map<XXH64_hash_t, std::vector<unsigned char>> MapType;
extern "C" {
    void* kale_map_create(){
        void* map = new MapType();

        return map;
    }

    void kale_map_free(void* rmap){
        MapType* map = (MapType*)rmap;
        delete map;
    }

    unsigned char* kale_map_get(void* rmap, XXH64_hash_t hash, size_t *outSize){
        MapType* map = (MapType*)rmap;

        if(map->contains(hash)){
            std::vector<unsigned char>* target = &map->at(hash);
            *outSize = target->size();
            return target->data();
        }

        return NULL;
    }

    void kale_map_store(void* rmap, XXH64_hash_t hash, unsigned char* data, size_t dataSize){
        MapType* map = (MapType*)rmap;

        (*map)[hash] = std::vector<unsigned char>(dataSize);

        memcpy(data, (*map)[hash].data(), dataSize);
    }
}