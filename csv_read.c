#include "csv2mmdb.h"
#include "tree.h"

void parse_prefix(char *ip_str, prefix_t *p)
{
    in_addr_t ip;

    char buf[INET_ADDRSTRLEN + 3];
    char *host_str = strsep(&ip_str, "/");
    inet_pton(AF_INET, host_str, &ip);

    p->host = ntohl(ip);

    if (!ip_str) {
        p->masklen = 32;
    } else {
        p->masklen = atoi(ip_str);
    }
}

void append_string(char ***arr, size_t *size, char *str)
{
  *size = *size + 1;
  *arr = (char**)realloc(*arr, *size * sizeof(char*));
  (*arr)[*size-1] = str;
}

char read_until_char(char *delimiters, char **str, size_t *size, FILE *fp)
{
  char buf[BUFSIZE], ch;
  size_t written_to_buffer = 0, nbuffers = 0;
  *size = 0;
  while(1) {
      ch = fgetc(fp);
      /* debug_print("read_until_char: READ %c (%d)\n", ch, ch); */
      /* printf("CHAR: %c %u %u\n", ch, *size, written_to_buffer); */
      if(strchr(delimiters, ch) || ch == EOF) {
          *str = realloc(*str, *size + 1);
          strncpy(*str+nbuffers*BUFSIZE, buf, written_to_buffer);
          (*str)[*size] = '\0';
          return ch;
      }

      if(written_to_buffer >= BUFSIZE) {
          *str = realloc(*str, (*size)+1);
          strncpy(*str+nbuffers*BUFSIZE, buf, written_to_buffer);
          written_to_buffer = 0;
          nbuffers++;
      }

      buf[written_to_buffer++] = ch;
      *size = *size + 1;
  }
  return 0;
}

size_t skip_to_char(char *delimiters, FILE *fp)
{
  char ch;
  size_t count = 0;
  while(1) {
    ch = fgetc(fp);
    count++;
    if(strchr(delimiters, ch) || ch == EOF)
      break;
  }
  return count;
}

void read_input_file(mmdb_tree_t *t, char *fname)
{
  FILE *fp = fopen(fname, "r");
  char *str = NULL;
  char **columns = NULL;
  size_t size = 0, ncolumns = 0, pos = 0;
  t->infile = fp;
  t->headers = NULL;
  t->num_headers = 0;
  char ch;
  // Load headers array
  while (1) {
      ch = read_until_char("\t\n", &str, &size, fp);
      pos += size + 1;
      debug_print("Col name: %s\t\t(len: %d, pos: %d)\t%d\n", str, size, pos, t->num_headers);
      append_string(&(t->headers), &(t->num_headers), str);
      str = NULL;
      if (ch == '\n')
        break;
  }
  prefix_t prefix;
  debug_print("Header finished at %d\n", pos);
  while(1) {
      ch = read_until_char("\t\n", &str, &size, fp);

      if (size == 0)
        break;

      pos += size + 1;

      if (ch != '\t') {
        fprintf(stderr, "IP range must be followed by TAB\n");
        exit(1);
      }

      debug_print("Inserting prefix %s with data %d\n", str, pos);
      parse_prefix(str, &prefix);
      free(str);
      str = NULL;
      insert_prefix(t, &prefix, pos);

      pos += skip_to_char("\n", fp);
      /* str[0] = '\0'; */
      if (ch == EOF)
        break;
  }
}
