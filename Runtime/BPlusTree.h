#define MAX_KEYS_PER_INTERNAL_NODE 3
#define MAX_KEYS_PER_LEAF_NODE 7

struct BPlusTreeNode;
typedef struct BPlusTreeNode **BPlusTree;

BPlusTree make_b_plus_tree();
int lookup_b_plus_tree(BPlusTree tree, unsigned long key);
void insert_b_plus_tree(BPlusTree tree, unsigned long key);
void destroy_b_plus_tree(BPlusTree tree);
