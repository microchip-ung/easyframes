#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIV_ROUND(a, b) (1 + ((a - 1) / b))
#define BIT_TO_BYTE(x) (DIV_ROUND(x, 8))

///////////////////////////////////////////////////////////////////////////////
typedef struct {
    size_t  size;
    uint8_t *data;
} buf_t;

void bfree(buf_t *b);
buf_t *balloc(size_t size);
buf_t *bclone(const buf_t *b);

typedef struct buf_list_element {
    struct buf_list_element *next;
    buf_t                    buf;
} buf_list_element_t;

void ble_free(buf_list_element_t *head);
buf_list_element_t *ble_alloc(size_t size);

buf_list_element_t *ble_tail(buf_list_element_t *head);

buf_list_element_t *ble_append(buf_list_element_t *head, buf_list_element_t *e);

buf_list_element_t *ble_append_buf(buf_list_element_t *head, buf_t *e);

typedef struct {
    size_t size;
    size_t capacity;
    buf_list_element_t *head;
} buf_list_t;

// debug feature, check invariants
void bl_check(buf_list_t *b);

void bl_reset(buf_list_t *b);
inline void bl_init(buf_list_t *b) { bl_reset(b); }
inline void bl_destroy(buf_list_t *b) { bl_reset(b); }

int bl_printf_append(buf_list_t *b, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));

//ssize_t bwrite(int fd, const buf_list_t *buf, ssize_t off, size_t count);
size_t bwrite_all(int fd, const buf_list_t *buf);

///////////////////////////////////////////////////////////////////////////////

void destruct_free(void *buf, void *cb);

#define GEN_ALLOC_CLONE_FREE(name)                                             \
static inline void name ## _free(name ## _t *f) {                              \
    destruct_free(f, (void *)&name ## _destruct);                              \
}                                                                              \
static inline name ## _t *name ## _alloc() {                                   \
    return (name ## _t *)calloc(1, sizeof(name ## _t));                        \
}                                                                              \
static inline name ## _t *name ## _clone(const name ## _t *src) {              \
    name ## _t *dst = name ## _alloc();                                        \
    if (!dst)                                                                  \
        return 0;                                                              \
    if (name ## _copy(dst, src) == 0) {                                        \
        return dst;                                                            \
    } else {                                                                   \
        free(dst);                                                             \
        return 0;                                                              \
    }                                                                          \
}

struct frame;
typedef int (*frame_fill_defaults_t)(struct frame *, int stack_idx);

typedef struct {
    const char *name;
    const char *help;
    int         bit_width;
    int         bit_offset;
    buf_t      *def;
    buf_t      *val;
} field_t;

int field_copy(field_t *dst, const field_t *src);
void field_destruct(field_t *f);
GEN_ALLOC_CLONE_FREE(field);

typedef struct {
    const char *name;
    const char *help;
    uint32_t    type;
    uint32_t    size;

    field_t    *fields;
    int         fields_size;

    int         offset_in_frame;

    frame_fill_defaults_t frame_fill_defaults;
} hdr_t;

int hdr_copy(hdr_t *dst, const hdr_t *src);
void hdr_destruct(hdr_t*f);
GEN_ALLOC_CLONE_FREE(hdr);

typedef struct frame {
#define FRAME_STACK_MAX 100
    hdr_t *stack[FRAME_STACK_MAX];
    int    stack_size;
    int    buf_size;
} frame_t;

int frame_copy(frame_t *dst, const frame_t *src);
void frame_destruct(frame_t *f);
GEN_ALLOC_CLONE_FREE(frame);


buf_t *parse_bytes(const char *s, int bytes);

field_t *find_field(hdr_t *h, const char *field);

void hdr_write_field(buf_t *b, int offset, const field_t *f, const buf_t *val);

void frame_reset(frame_t *f);
hdr_t *frame_clone_and_push_hdr(frame_t *f, hdr_t *h);

int hdr_copy_to_buf(hdr_t *hdr, int offset, buf_t *buf);
int hdr_parse_fields(hdr_t *hdr, int argc, const char *argv[]);

buf_t *frame_to_buf(frame_t *f);

void init_frame_data_all();
void uninit_frame_data_all();

uint16_t inet_chksum(uint32_t sum, const uint16_t *buf, int length);
void uninit_frame_data(hdr_t *h);
void def_val(hdr_t *h, const char *field, const char *def);
void def_offset(hdr_t *h);
int ether_type_fill_defaults(struct frame *f, int stack_idx);

void field_help(field_t *f, int indent);
void hdr_help(hdr_t **hdr, int size, int indent, int show_fields);

typedef enum {
    HDR_TMPL_ETH,
    HDR_TMPL_CTAG,
    HDR_TMPL_STAG,
    HDR_TMPL_ARP,
    HDR_TMPL_IPV4,
    HDR_TMPL_UDP,
    HDR_TMPL_PAYLOAD,

    HDR_TMPL_SIZE,
} hdr_tmpl_t;

extern hdr_t *hdr_tmpls[HDR_TMPL_SIZE];

#ifdef __cplusplus
}
#endif
