//
// Created by haidy on 20-7-13.
//

#ifndef NETWORK_LIST_H
#define NETWORK_LIST_H

typedef struct nip_link_list LinkList;

LinkList *LinkList_new();

void *LinkList_header(LinkList *list);

void *LinkList_footer(LinkList *list);

void LinkList_add(LinkList *list, void *data);

void *LinkList_remove_header(LinkList *list);

void *LinkList_iterator(LinkList *list);

void *LinkList_next(void *it);

void *LinkList_value(void *it);

#endif //NETWORK_LIST_H
