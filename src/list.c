//
// Created by haidy on 20-7-13.
//
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "list.h"

typedef struct nip_list_node Node;
struct nip_list_node {
    Node *next;
    void *data;
};

struct nip_link_list {
    Node *header;
    Node *footer;
};

LinkList *LinkList_new() {
    LinkList *list = malloc(sizeof(LinkList));
    list->header = NULL;
    list->footer = NULL;
    return list;
}

void *LinkList_header(LinkList *list) {
    if (list == NULL) return NULL;
    return list->header != NULL ? list->header->data : NULL;
}

void *LinkList_footer(LinkList *list) {
    if (list == NULL) return NULL;
    return list->footer != NULL ? list->footer->data : NULL;
}

void LinkList_add(LinkList *list, void *data) {
    if (list == NULL) return;

    Node *node = malloc(sizeof(Node));
    node->data = data;
    node->next = NULL;

    if (list->footer == NULL) {
        list->header = list->footer = node;
    } else {
        list->footer->next = node;
        list->footer = node;
    }
}

void *LinkList_remove_header(LinkList *list) {
    if (list == NULL) return NULL;
    if (list->header == NULL) return NULL;

    if (list->header == list->footer) {
        void *data = list->header->data;
        free(list->header);
        list->header = list->footer = NULL;
        return data;
    }

    Node *header = list->header;
    void *data = header->data;
    list->header = header->next;
    free(header);
    return data;
}

void *LinkList_iterator(LinkList *list) {
    return list->header;
}

void *LinkList_next(void *it) {
    Node *node = it;
    return node->next;
}

void *LinkList_value(void *it) {
    Node *node = it;
    return node->data;
}