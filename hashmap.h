#pragma once

#include <stdlib.h>

#include "linked_list.h"

#define MAP_INIT_SIZE 16
#define MAP_EXTEND_SIZE 16

#define hashmap_define(name, tk, tv) \
    typedef struct { \
        tk key; \
        tv value; \
    } mapnode_##name##_t; \
    linked_list_define(mapnode_##name##_t); \
    typedef struct hashmap { \
        int size; \
        int capacity; \
        tk (*hash)(tk); \
        llof(mapnode_##name##_t) **buckets; \
    } hashmap_##name##_t; \
    hashmap_##name##_t *hashmap_##name##_new(tk (*hash)(tk)) \
    { \
        hashmap_##name##_t *map = (hashmap_##name##_t *)malloc(sizeof(hashmap_##name##_t)); \
        map->capacity = MAP_INIT_SIZE; \
        map->size = 0; \
        map->hash = hash; \
        map->buckets = (llof(mapnode_##name##_t) **)malloc(sizeof(llof(mapnode_##name##_t) *) * map->capacity); \
        for (int i = 0; i < map->capacity; i++) \
        { \
            map->buckets[i] = NULL; \
        } \
        return map; \
    } \
    void hashmap_##name##_free(hashmap_##name##_t *map) \
    { \
        for (int i = 0; i < map->capacity; i++) \
        { \
            linked_list_free(mapnode_##name##_t, map->buckets[i]); \
        } \
        free(map->buckets); \
        free(map); \
    } \
    int hashmap_##name##_contains_key(hashmap_##name##_t *map, tk key) \
    { \
        for (llof(mapnode_##name##_t) *node = map->buckets[map->hash(key) % map->capacity]; \
            node != NULL; \
            node = node->next) \
        { \
            if (node->data.key == key) \
            { \
                return 1; \
            } \
        } \
        return 0; \
    } \
    tv hashmap_##name##_get_or_default(hashmap_##name##_t *map, tk key, tv def) \
    { \
        for (llof(mapnode_##name##_t) *node = map->buckets[map->hash(key) % map->capacity]; \
            node != NULL; \
            node = node->next) \
        { \
            if (node->data.key == key) \
            { \
                return node->data.value; \
            } \
        } \
        return def; \
    } \
    void hashmap_##name##_ensure_capacity(hashmap_##name##_t *map) \
    { \
        if (map->size >= map->capacity) \
        { \
            map->capacity += MAP_EXTEND_SIZE; \
            map->buckets = (llof(mapnode_##name##_t) **)realloc(map->buckets, sizeof(llof(mapnode_##name##_t) *) * map->capacity); \
            for (int i = map->capacity - MAP_EXTEND_SIZE; i < map->capacity; i++) \
            { \
                map->buckets[i] = NULL; \
            } \
        } \
    } \
    void hashmap_##name##_put(hashmap_##name##_t *map, tk key, tv value) \
    { \
        hashmap_##name##_ensure_capacity(map); \
        int hash = map->hash(key) % map->capacity; \
        for (llof(mapnode_##name##_t) *node = map->buckets[hash]; node != NULL; node = node->next) \
        { \
            if (node->data.key == key) \
            { \
                node->data.value = value; \
                return; \
            } \
        } \
        linked_list_append(mapnode_##name##_t, map->buckets[hash], ((mapnode_##name##_t){key, value})); \
        map->size++; \
    } \
    void hashmap_##name##_remove(hashmap_##name##_t *map, tk key) \
    { \
        int hash = map->hash(key) % map->capacity; \
        llof(mapnode_##name##_t) *prev = NULL; \
        for (llof(mapnode_##name##_t) *node = map->buckets[hash]; node != NULL; node = node->next) \
        { \
            if (node->data.key == key) \
            { \
                if (prev == NULL) \
                { \
                    map->buckets[hash] = node->next; \
                } \
                else \
                { \
                    prev->next = node->next; \
                } \
                free(node); \
                map->size--; \
                return; \
            } \
            prev = node; \
        } \
    }
