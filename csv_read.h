#ifndef __CSV_READ_H__
#define __CSV_READ_H__

void parse_prefix(char *ip_str, prefix_t *p);
void append_string(char ***arr, size_t *size, char *str);
char read_until_char(char *delimiters, char **str, size_t *size, FILE *fp);
size_t skip_to_char(char *delimiters, FILE *fp);
void read_input_file(mmdb_tree_t *t, char *fname);

#endif
