#include "ef.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>

void bfree(buf_t *b) {
    if (!b)
        return;

    free(b);
}

buf_t *balloc(size_t size) {
    buf_t *b;
    uint8_t *d;

    d = (uint8_t *)calloc(1, sizeof(buf_t) + size);
    if (!d)
        return 0;

    b = (buf_t *)d;
    b->size = size;
    b->data = d + sizeof(buf_t);

    return b;
}

buf_t *bclone(const buf_t *b) {
    if (!b)
        return 0;

    buf_t *bb = balloc(b->size);
    if (!bb)
        return 0;

    memcpy(bb->data, b->data, b->size);

    return bb;
}

int bequal(const buf_t *a, const buf_t *b) {
    if ((a && !b) || (!a && b))
        return 0;

    if (!a && !b)
        return 1;

    if (a->size != b->size)
        return 0;

    return memcmp(a->data, b->data, a->size) == 0;
}

int bequal_mask(const buf_t *rx_frame, const buf_t *expected_frame,
                const buf_t *mask, int padding) {
    int i = 0;

    if ((rx_frame && !expected_frame) || (!rx_frame && expected_frame))
        return 0;

    if (!rx_frame && !expected_frame)
        return 1;

    if (padding < 0)
        return 0;

    if (rx_frame->size != expected_frame->size + padding)
        return 0;

    if (mask == 0)
        return memcmp(rx_frame->data, expected_frame->data, rx_frame->size) == 0;

    // Notice, rx_frame->size may be smaller than expected_frame->size
    for (i = 0; i < rx_frame->size; ++i) {
        unsigned char a_, b_, m_;
        a_ = rx_frame->data[i];
        b_ = expected_frame->data[i];
        if (i >= mask->size) {
            m_ = 0xff;
        } else {
            m_ = mask->data[i];
        }

        if ((a_ & m_) != (b_ & m_)) {
            return 0;
        }
    }

    return 1;
}

void ble_free(buf_list_element_t *b) {
    if (!b)
        return;

    if (b->next)
        ble_free(b->next);

    free(b);
}

buf_list_element_t *ble_alloc(size_t size) {
    buf_list_element_t *b;
    uint8_t *d;

    d = (uint8_t *)calloc(1, sizeof(buf_list_element_t) + size);
    if (!d)
        return 0;

    b = (buf_list_element_t *)d;
    b->next = 0;
    b->buf.size = size;
    b->buf.data = d + sizeof(buf_list_element_t);

    return b;
};

buf_list_element_t *ble_tail(buf_list_element_t *head) {
    while (head->next)
        head = head->next;

    return head;
}

buf_list_element_t *ble_append(buf_list_element_t *head,
                               buf_list_element_t *e) {
    ble_tail(head)->next = e;
    return e;
}

buf_list_element_t *ble_append_buf(buf_list_element_t *head, buf_t *e) {
    buf_list_element_t *le = ble_alloc(e->size);

    if (!le)
        return 0;

    memcpy(le->buf.data, e->data, e->size);
    bfree(e);

    return ble_append(head, le);
}

void bl_reset(buf_list_t *b) {
    ble_free(b->head);
    memset(b, 0, sizeof(*b));
}

void bl_check(buf_list_t *b) {
    size_t s;
    buf_list_element_t *head;

    if (!b)
        return;

    assert(b->capacity >= b->size);

    // Check that sum of all elements matches the list capacity
    s = 0;
    head = b->head;
    while (head) {
        s += head->buf.size;
        head = head->next;
    }

    assert(s == b->capacity);

    // Check that the free capacity is smaller than the lastest block
    if (b->capacity > b->size) {
        assert((b->capacity - b->size) < ble_tail(b->head)->buf.size);
    }

    // Check that assert is turned on
    assert(0);
}

int po(const char *fmt, ...) {
    int res;
    va_list ap;
    va_start(ap, fmt);
    res = vdprintf(1, fmt, ap);
    va_end(ap);
    return res;
}

int pe(const char *fmt, ...) {
    int res;
    va_list ap;
    va_start(ap, fmt);
    res = vdprintf(2, fmt, ap);
    va_end(ap);
    return res;
}

int bl_printf_append(buf_list_t *b, const char *fmt, ...) {
    char *data_end;
    va_list ap;
    int str_size;
    size_t free_space;
    size_t alloc_size;
    buf_list_element_t *tail, *new_element;

    bl_check(b);

    free_space = b->capacity - b->size;
    if (free_space) {
        tail = ble_tail(b->head);
        data_end = (char *)tail->buf.data + tail->buf.size - free_space;
    } else {
        data_end = 0;
    }

    va_start(ap, fmt);
    str_size = vsnprintf(data_end, free_space, fmt, ap);
    va_end(ap);

    if (str_size < 0)
        return str_size;

    if (str_size <= free_space) {
        b->size += str_size;
        bl_check(b);

        return str_size;
    }

    alloc_size = 4096;
    if (str_size > alloc_size)
        alloc_size = str_size;

    new_element = ble_alloc(alloc_size);
    if (!new_element)
        return -1;

    va_start(ap, fmt);
    str_size = vsnprintf((char *)new_element->buf.data, alloc_size, fmt, ap);
    va_end(ap);

    if (free_space) {
        memcpy(data_end, new_element->buf.data, free_space);
        memmove(new_element->buf.data, new_element->buf.data + free_space,
                str_size - free_space);
    }

    b->size += str_size;
    b->capacity += alloc_size;
    bl_check(b);

    return str_size;
}

buf_t *bprintf(const char *fmt, ...) {
    buf_t *b;
    va_list ap;
    size_t str_size;

    va_start(ap, fmt);
    str_size = vsnprintf(0, 0, fmt, ap);
    va_end(ap);

    b = balloc(str_size + 1);

    if (!b)
        return b;

    va_start(ap, fmt);
    str_size = vsnprintf((char *)b->data, b->size, fmt, ap);
    va_end(ap);

    return b;
}

