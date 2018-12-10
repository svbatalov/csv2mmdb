#ifndef __CSV2MMDB_H__
#define __CSV2MMDB_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>

#define DEBUG 1

#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define BUFSIZE 1024

typedef enum {
    /* Normal types 1-7 (that fit into first 3 bits of control byte) */
    MMDB_POINTER=1, MMDB_STRING, MMDB_DOUBLE, MMDB_BYTES, MMDB_UINT16, MMDB_UINT32, MMDB_MAP,
    /* Extended types */
    MMDB_INT32, MMDB_UINT64, MMDB_UINT128, MMDB_ARRAY, MMDB_CACHE, MMDB_DATA_END, MMDB_BOOL, MMDB_FLOAT
} mmdb_type_t;

typedef uint32_t ptr_t;

typedef struct {
    in_addr_t host;
    uint8_t masklen;
} prefix_t;

typedef struct {
  int val;
} mmdb_node_data_t;

typedef struct mmdb_tree {
    struct mmdb_tree *left;
    struct mmdb_tree *right;
    uint32_t index;
    mmdb_node_data_t *data;
} mmdb_tree_node_t;

typedef struct {
    mmdb_tree_node_t *root;

    FILE *outfile;
    FILE *infile;
    size_t data_written;

    uint32_t node_count;
    uint16_t record_size;
    uint16_t ip_version;
    char *database_type;
    /* char **languages; */
    uint16_t binary_format_major_version;
    uint16_t binary_format_minor_version;
    uint64_t build_epoch;
    char *description_en;

    char **headers;
    size_t num_headers;
    size_t *header_offset;
} mmdb_tree_t;

typedef struct {
    int parent_data;
    mmdb_tree_t *tree;
} mmdb_writer_data_t;

#endif
