#include "hashmap.h"

#include <stdlib.h>

#define MAP_INIT_SIZE 16
#define MAP_EXTEND_SIZE 16

linked_list_define(mapnode_t);


hashmap_t *hashmap_init(int (*hash)(int))
{
    hashmap_t *map = (hashmap_t *)malloc(sizeof(hashmap_t));
    map->capacity = MAP_INIT_SIZE;
    map->size = 0;
    map->hash = hash;
    map->buckets = (ll_t **)malloc(sizeof(ll_t *) * map->capacity);
    for (int i = 0; i < map->capacity; i++)
    {
        map->buckets[i] = NULL;
    }
    return map;
}

void hashmap_free(hashmap_t *map)
{
    for (int i = 0; i < map->capacity; i++)
    {
        linked_list_free(mapnode_t, map->buckets[i]);
    }
    free(map->buckets);
    free(map);
}

int hashmap_contains_key(hashmap_t *map, int key)
{
    for (ll_t *node = map->buckets[map->hash(key) % map->capacity];
         node != NULL;
         node = node->next)
    {
        if (node->data.key == key)
        {
            return 1;
        }
    }
    return 0;
}

int hashmap_get(hashmap_t *map, int key)
{
    for (ll_t *node = map->buckets[map->hash(key) % map->capacity];
         node != NULL;
         node = node->next)
    {
        if (node->data.key == key)
        {
            return node->data.value;
        }
    }
    return 0;
}

void hashmap_ensure_capacity(hashmap_t *map)
{
    if (map->size >= map->capacity)
    {
        map->capacity += MAP_EXTEND_SIZE;
        map->buckets = (ll_t **)realloc(map->buckets, sizeof(ll_t *) * map->capacity);
        for (int i = map->capacity - MAP_EXTEND_SIZE; i < map->capacity; i++)
        {
            map->buckets[i] = NULL;
        }
    }
}

void hashmap_put(hashmap_t *map, int key, int value)
{
    hashmap_ensure_capacity(map);
    int hash = map->hash(key) % map->capacity;
    for (ll_t *node = map->buckets[hash]; node != NULL; node = node->next)
    {
        if (node->data.key == key)
        {
            node->data.value = value;
            return;
        }
    }
    linked_list_append(mapnode_t, map->buckets[hash], ((mapnode_t){key, value}));
    map->size++;
}
