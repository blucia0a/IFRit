#include "stdio.h"
#include "stdlib.h"

#include "BPlusTree.h"

struct BPlusTreeInternalNode {
  int count;
  unsigned long keys[MAX_KEYS_PER_INTERNAL_NODE];
  struct BPlusTreeNode *children[MAX_KEYS_PER_INTERNAL_NODE + 1];
};

struct BPlusTreeLeafNode {
  int count;
  unsigned long keys[MAX_KEYS_PER_LEAF_NODE];
};

struct BPlusTreeNode {
  int is_leaf;
  union {
    struct BPlusTreeInternalNode internal;
    struct BPlusTreeLeafNode leaf;
  } node;
};

struct BPlusTreeNode *
make_b_plus_tree_internal_node(struct BPlusTreeNode *left,
			       struct BPlusTreeNode *right,
			       unsigned long key) {
  struct BPlusTreeNode *node = (struct BPlusTreeNode *)
    calloc(1, sizeof(struct BPlusTreeNode));
  node->is_leaf = 0;
  node->node.internal.count = 1;
  node->node.internal.keys[0] = key;
  node->node.internal.children[0] = left;
  node->node.internal.children[1] = right;
  return node;
}

struct BPlusTreeNode *make_b_plus_tree_leaf_node() {
  struct BPlusTreeNode *node = (struct BPlusTreeNode *)
    calloc(1, sizeof(struct BPlusTreeNode));
  node->is_leaf = 1;
  node->node.leaf.count = 0;
  return node;
}

BPlusTree make_b_plus_tree() {
  BPlusTree tree = (BPlusTree) malloc(sizeof (struct BPlusTreeNode *));
  *tree = make_b_plus_tree_leaf_node();
  return tree;
}

int lookup_b_plus_tree_node(struct BPlusTreeNode *node, unsigned long key) {
  int i;
  if (node->is_leaf) {
    for (i = 0; i < node->node.leaf.count; i++) {
      if (key == node->node.leaf.keys[i]) {
	return 1;
      }
    }
    return 0;
  } else {
    if (key < node->node.internal.keys[0]) {
      return lookup_b_plus_tree_node(node->node.internal.children[0], key);
    }
    for (i = 1; i < node->node.internal.count; i++) {
      if (key < node->node.internal.keys[i]) {
	return lookup_b_plus_tree_node(node->node.internal.children[i], key);
      }
    }
    return lookup_b_plus_tree_node(node->node.internal.children[node->node.internal.count], key);
  }
}

int lookup_b_plus_tree(BPlusTree tree, unsigned long key) {
  return lookup_b_plus_tree_node(*tree, key);
}

struct BPlusTreeAllocatedNodeInfo {
  struct BPlusTreeNode *new_node;
  unsigned long divider_key;
};

struct BPlusTreeAllocatedNodeInfo *
insert_b_plus_tree_leaf_node(struct BPlusTreeNode *node, unsigned long key) {
  int i;
  for (i = 0; i < node->node.leaf.count; i++) {
    if (key == node->node.leaf.keys[i]) {
      fprintf(stderr, "[IFRit] Error: inserted existing key into B+ tree\n");
      exit(-1);
    } else if (key < node->node.leaf.keys[i]) {
      break;
    }
  }

  if (node->node.leaf.count < MAX_KEYS_PER_LEAF_NODE) {
    int j;
    for (j = node->node.leaf.count; j > i; j--) {
      node->node.leaf.keys[j] = node->node.leaf.keys[j - 1];
    }
    node->node.leaf.keys[i] = key;
    node->node.leaf.count++;
    return NULL;
  }

  // Case when the leaf node is full. SPLIT the node into two leaf
  // nodes.
  int j, k;
  int splitPoint = (MAX_KEYS_PER_LEAF_NODE + 1) / 2;
  unsigned long temp[MAX_KEYS_PER_LEAF_NODE + 1];

  // Create temporary arrays to store all of the keys and values,
  // including the newly inserted pair.
  for (j = 0, k = 0; j < MAX_KEYS_PER_LEAF_NODE + 1; j++) {
    if (j == i) {
      temp[j] = key;
    } else {
      temp[j] = node->node.leaf.keys[k];
      k++;
    }
  }

  // Copy the first halves of the temporary arrays into the old node.
  node->node.leaf.count = splitPoint;
  for (j = 0; j < node->node.leaf.count; j++) {
    node->node.leaf.keys[j] = temp[j];
  }

  // For debugging - erase the elements that will be moved to the new
  // node.
  for (j = node->node.leaf.count; j < MAX_KEYS_PER_LEAF_NODE; j++) {
    node->node.leaf.keys[j] = 0;
  }

  // Create new node and copy the second halves of the temporary
  // arrays into the new node.
  struct BPlusTreeNode *new_node = (struct BPlusTreeNode *)
    calloc(1, sizeof(struct BPlusTreeNode));
  new_node->is_leaf = 1;
  new_node->node.leaf.count = MAX_KEYS_PER_LEAF_NODE + 1 - splitPoint;
  for (j = 0; j < new_node->node.leaf.count; j++) {
    new_node->node.leaf.keys[j] = temp[j + splitPoint];
  }

  // Return the new node to indicate that a split occurred. The new
  // key is the first element of the new node.
  struct BPlusTreeAllocatedNodeInfo *info =
    (struct BPlusTreeAllocatedNodeInfo *)
    malloc(sizeof(struct BPlusTreeAllocatedNodeInfo));
  info->new_node = new_node;
  info->divider_key = new_node->node.leaf.keys[0];
  return info;
}

struct BPlusTreeAllocatedNodeInfo *
insert_b_plus_tree_node(struct BPlusTreeNode *node, unsigned long key);

struct BPlusTreeAllocatedNodeInfo *
insert_b_plus_tree_internal_node(struct BPlusTreeNode *node,
				 unsigned long key) {
  int i, j, k;
  for (i = 0; i < node->node.internal.count; i++) {
    if (key < node->node.internal.keys[i]) {
      break;
    }
  }

  struct BPlusTreeAllocatedNodeInfo *info =
    insert_b_plus_tree_node(node->node.internal.children[i], key);

  if (info == NULL) {
    return NULL;
  }

  struct BPlusTreeNode *new_child = info->new_node;
  unsigned long new_key = info->divider_key;
  free(info);

  if (node->node.internal.count < MAX_KEYS_PER_INTERNAL_NODE) {
    int j;
    for (j = node->node.internal.count; j > i; j--) {
      node->node.internal.keys[j] = node->node.internal.keys[j - 1];
      node->node.internal.children[j + 1] = node->node.internal.children[j];
    }
    node->node.internal.keys[i] = new_key;
    node->node.internal.children[i + 1] = new_child;
    node->node.internal.count++;
    return NULL;
  }

  // This node is full. SPLIT.

  // Copy the keys and children, including the inserted key, into
  // temporary arrays for easy splitting.
  unsigned long temp_keys[MAX_KEYS_PER_INTERNAL_NODE + 1];
  struct BPlusTreeNode *temp_children[MAX_KEYS_PER_INTERNAL_NODE + 2];
  temp_children[0] = node->node.internal.children[0];
  for (j = 0, k = 0; j < MAX_KEYS_PER_INTERNAL_NODE + 1; j++) {
    if (j == i) {
      temp_keys[j] = new_key;
      temp_children[j + 1] = new_child;
    } else {
      temp_keys[j] = node->node.internal.keys[k];
      temp_children[j + 1] = node->node.internal.children[k + 1];
      k++;
    }
  }

  // The index of the "split." The key here will be pushed up to the
  // parent node.
  int splitPoint = (MAX_KEYS_PER_INTERNAL_NODE + 1) / 2;

  // Copy the first half of the temp arrays into the original node.
  node->node.internal.count = splitPoint;
  for (j = 0; j < node->node.internal.count; j++) {
    node->node.internal.keys[j] = temp_keys[j];
    node->node.internal.children[j + 1] = temp_children[j + 1];
  }

  // For debugging - erase the deleted entries at the end of the
  // original node.
  for (j = node->node.internal.count; j < MAX_KEYS_PER_INTERNAL_NODE; j++) {
    node->node.internal.keys[j] = 0;
    node->node.internal.children[j + 1] = NULL;
  }

  // Create a new node and copy the second half of the temp arrays
  // into this second node.
  struct BPlusTreeNode *new_node =
    (struct BPlusTreeNode *) calloc(1, sizeof(struct BPlusTreeNode));
  new_node->is_leaf = 0;
  new_node->node.internal.count = MAX_KEYS_PER_INTERNAL_NODE - splitPoint;
  new_node->node.internal.children[0] = temp_children[splitPoint + 1];
  for (j = 0; j < new_node->node.internal.count; j++) {
    new_node->node.internal.keys[j] = temp_keys[j + splitPoint + 1];
    new_node->node.internal.children[j + 1] = temp_children[j + splitPoint + 2];
  }

  // Return the newly-allocated node and the key at the split point.
  info = (struct BPlusTreeAllocatedNodeInfo *)
    malloc(sizeof(struct BPlusTreeAllocatedNodeInfo));
  info->new_node = new_node;
  info->divider_key = temp_keys[splitPoint];
  return info;
}

struct BPlusTreeAllocatedNodeInfo *
insert_b_plus_tree_node(struct BPlusTreeNode *node, unsigned long key) {
  if (node->is_leaf) {
    return insert_b_plus_tree_leaf_node(node, key);
  } else {
    return insert_b_plus_tree_internal_node(node, key);
  }
}

void insert_b_plus_tree(BPlusTree tree, unsigned long key) {
  struct BPlusTreeAllocatedNodeInfo *info = insert_b_plus_tree_node(*tree, key);

  if (info == NULL) {
    return;
  }

  *tree = make_b_plus_tree_internal_node(*tree, info->new_node,
					 info->divider_key);
  free(info);
}

void destroy_b_plus_tree_node(struct BPlusTreeNode *node) {
  if (node->is_leaf) {
    free(node);
  } else {
    int i;
    for (i = 0; i <= node->node.internal.count; i++) {
      destroy_b_plus_tree_node(node->node.internal.children[i]);
    }
    free(node);
  }
}

void destroy_b_plus_tree(BPlusTree tree) {
  destroy_b_plus_tree_node(*tree);
  free(tree);
}
