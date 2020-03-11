# Copyright (c) 2020 The Linux Foundation. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

'''
 :  radix_tree_root is the address of root node


            struct radix_tree_root {
               [0x0] spinlock_t xa_lock;
              [0x18] gfp_t gfp_mask;
              [0x20] struct radix_tree_node *rnode;
            }
    get_radix_tree_root will return the rnode
    walk_radix_tree_node start with this rnode
 '''
RADIX_TREE_ENTRY_MASK =	3
RADIX_TREE_INTERNAL_NODE = 1
RADIX_TREE_MAP_SHIFT = 6
RADIX_TREE_MAP_SIZE = (1 << RADIX_TREE_MAP_SHIFT)


class RadixTreeWalker(object):
    def __init__(self, ramdump):
        self.ramdump = ramdump

    def get_radix_tree_root(self, radix_tree_root):
        rnode_offset = self.ramdump.field_offset('struct radix_tree_root', 'rnode')
        rnode_addr = self.ramdump.read_word(radix_tree_root + rnode_offset)
        return rnode_addr

    def entry_to_node(self, rbnode):
        return rbnode & ~RADIX_TREE_INTERNAL_NODE

    def radix_tree_is_internal_node(self, rbnode):
        return (rbnode & RADIX_TREE_ENTRY_MASK) == RADIX_TREE_INTERNAL_NODE

    def walk_radix_tree_node(self, radix_tree_node, func):

        if self.radix_tree_is_internal_node(radix_tree_node):
            radix_tree_node = self.entry_to_node(radix_tree_node)

        rnode_shift_offset = self.ramdump.field_offset('struct radix_tree_node', 'shift')
        slots_offset = self.ramdump.field_offset('struct radix_tree_node', 'slots')
        pointer_size = self.ramdump.sizeof('struct radix_tree_node *')

        shift = self.ramdump.read_byte(radix_tree_node + rnode_shift_offset)

        height = (shift / RADIX_TREE_MAP_SHIFT) + 1
        for off in range(0, RADIX_TREE_MAP_SIZE):
            slot = 0
            shift = (height - 1) * RADIX_TREE_MAP_SHIFT
            slot = self.ramdump.read_word(radix_tree_node + slots_offset + pointer_size * off)
            if slot is 0:
                continue
            radix_tree_node_next = slot
            # RADIX_TREE_INTERNAL_NODE mean we are not leaf
            if self.radix_tree_is_internal_node(slot):
                slot = self.entry_to_node(slot)
            else:
                # now we are going to handle our data on this leaf node
                func(slot)
            if height > 1:
                self.walk_radix_tree_node(radix_tree_node_next, func)

    def walk_radix_tree(self, radix_tree_root, func):
        radix_tree_node = self.get_radix_tree_root(radix_tree_root)
        self.walk_radix_tree_node(radix_tree_node, func)
