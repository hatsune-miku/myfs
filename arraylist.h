#pragma once

#include <stdlib.h>

#define ARRAY_INIT_SIZE 16

#define arraylist_define(name, type) \
    typedef struct { \
        type *data; \
        int size; \
        int capacity; \
    } arraylist_##name##_t; \
    arraylist_##name##_t *arraylist_##name##_new() { \
        arraylist_##name##_t *list = malloc(sizeof(arraylist_##name##_t)); \
        list->data = malloc(sizeof(type) * ARRAY_INIT_SIZE); \
        list->size = 0; \
        list->capacity = ARRAY_INIT_SIZE; \
        return list; \
    } \
    void arraylist_##name##_free(arraylist_##name##_t *list) { \
        free(list->data); \
        free(list); \
    } \
    void arraylist_##name##_add(arraylist_##name##_t *list, type value) { \
        if (list->size == list->capacity) { \
            list->capacity *= 2; \
            list->data = realloc(list->data, sizeof(type) * list->capacity); \
        } \
        list->data[list->size++] = value; \
    } \
    type arraylist_##name##_get(arraylist_##name##_t *list, int index) { \
        return list->data[index]; \
    } \
    void arraylist_##name##_set(arraylist_##name##_t *list, int index, type value) { \
        list->data[index] = value; \
    } \
    void arraylist_##name##_remove(arraylist_##name##_t *list, int index) { \
        for (int i = index; i < list->size - 1; i++) { \
            list->data[i] = list->data[i + 1]; \
        } \
        list->size--; \
    }

