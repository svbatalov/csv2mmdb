#include "csv2mmdb.h"
#include "tree.h"
#include "csv_read.h"
#include "mmdb_write.h"

int main(int argc, char **argv)
{
  prefix_t prefix;
  mmdb_tree_t *tree = make_tree();

  /* printf("node_size=%d\n", sizeof(mmdb_tree_node_t)); */
  /* exit(1); */

  char * infile = argc > 1 ? argv[1] : "./test.tsv";
  char * outfile = argc > 2 ? argv[2] : "./test.mmdb";

  char buf[INET_ADDRSTRLEN+3] = "255.255.0.0/16";
  /* parse_prefix(buf, &prefix); */
  /* insert_prefix(tree, &prefix, 0); */

  /* strcpy(buf, "1.2.3.4/24"); */
  /* parse_prefix(buf, &prefix); */
  /* insert_prefix(tree, &prefix, 321); */

  /* strcpy(buf, "1.2.3.4"); */
  /* parse_prefix(buf, &prefix); */
  /* insert_prefix(tree, &prefix, 111); */

  FILE *fp = fopen(outfile, "w");
  /* mmdb_write_tree(tree, fp); */

  /* mmdb_write_pointer(8, fp); */
  /* mmdb_write_metadata(tree, fp); */

  printf("Building tree..\n");
  read_input_file(tree, infile);

  traverse_pre_order(tree->root, &print_node, NULL);

  printf("Node count: %d\n", tree->node_count);

  printf("Writing file %s\n", outfile);
  mmdb_write_file(tree, fp);
  printf("Done\n");

  /* mmdb_write_data(tree, 101, fp); */

  fclose(fp);
}
