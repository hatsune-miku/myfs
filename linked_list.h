#pragma once

#include <stdlib.h>

#define llof(type) \
    struct ll_##type##_t

#define linked_list_define(type) \
    llof(type) { \
        type data; \
        llof(type) *next; \
    }

#define linked_list_new(type) \
    (llof(type)*)malloc(sizeof(llof(type)))

#define linked_list_append(type, list, v) \
    { \
        llof(type) *node = linked_list_new(type); \
        node->data = v; \
        node->next = NULL; \
        if (list == NULL) { \
            list = node; \
        } else { \
            llof(type) *last = list; \
            while (last->next != NULL) { \
                last = last->next; \
            } \
            last->next = node; \
        } \
    }

#define linked_list_free(type, list) \
    { \
        llof(type) *node = list; \
        while (node != NULL) { \
            llof(type) *next = node->next; \
            free(node); \
            node = next; \
        } \
    }

#define linked_list_insert(type, list, data, index) \
    { \
        llof(type) *node = linked_list_new(type); \
        node->data = data; \
        node->next = NULL; \
        if (list == NULL) { \
            list = node; \
        } else { \
            llof(type) *last = list; \
            int i = 0; \
            while (last->next != NULL && i < index) { \
                last = last->next; \
                i++; \
            } \
            node->next = last->next; \
            last->next = node; \
        } \
    }

#define linked_list_remove(type, list, index) \
    { \
        if (list != NULL) { \
            llof(type) *node = list; \
            if (index == 0) { \
                list = node->next; \
                free(node); \
            } else { \
                int i = 0; \
                while (node->next != NULL && i < index - 1) { \
                    node = node->next; \
                    i++; \
                } \
                llof(type) *next = node->next->next; \
                free(node->next); \
                node->next = next; \
            } \
        } \
    }
