#include "assert.h"
#include "stdio.h"

#include "BPlusTree.h"

int main(int args, char *argv[]) {
  unsigned long i, j;
  BPlusTree tree = make_b_plus_tree();

  assert(!lookup_b_plus_tree(tree, 5));

  for(i = 0; i < MAX_KEYS_PER_LEAF_NODE; i++) {
    insert_b_plus_tree(tree, i);
  }

  for(i = 0; i < MAX_KEYS_PER_LEAF_NODE; i++) {
    assert(lookup_b_plus_tree(tree, i));
  }
  assert(!lookup_b_plus_tree(tree, MAX_KEYS_PER_LEAF_NODE));

  for(i = 0; i < MAX_KEYS_PER_LEAF_NODE; i++) {
    insert_b_plus_tree(tree, i + MAX_KEYS_PER_LEAF_NODE);
  }

  for(i = 0; i < MAX_KEYS_PER_LEAF_NODE; i++) {
    assert(lookup_b_plus_tree(tree, i));
  }
  for(i = 0; i < MAX_KEYS_PER_LEAF_NODE; i++) {
    assert(lookup_b_plus_tree(tree, i + MAX_KEYS_PER_LEAF_NODE));
  }
  assert(!lookup_b_plus_tree(tree, 2 * MAX_KEYS_PER_LEAF_NODE));

  destroy_b_plus_tree(tree);

  tree = make_b_plus_tree();
  for (i = 0; i <= MAX_KEYS_PER_INTERNAL_NODE; i++) {
    for (j = 0; j < MAX_KEYS_PER_LEAF_NODE; j++) {
      insert_b_plus_tree(tree, i * MAX_KEYS_PER_LEAF_NODE + j);
    }
  }
  for (i = 0; i <= MAX_KEYS_PER_INTERNAL_NODE; i++) {
    for (j = 0; j < MAX_KEYS_PER_LEAF_NODE; j++) {
      assert(lookup_b_plus_tree(tree, i * MAX_KEYS_PER_INTERNAL_NODE + j));
    }
  }
  destroy_b_plus_tree(tree);

  printf("Passed\n");

  return 0;
}
