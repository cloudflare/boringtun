// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::device::peer::AllowedIP;

use std::cmp::min;
use std::iter::FromIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A trie of IP/cidr addresses
pub struct AllowedIps<D> {
    v4: Option<Node32<D>>,
    v6: Option<Node128<D>>,
}

impl<D> Default for AllowedIps<D> {
    fn default() -> Self {
        Self { v4: None, v6: None }
    }
}

impl<'a> FromIterator<&'a AllowedIP> for AllowedIps<()> {
    fn from_iter<I: IntoIterator<Item = &'a AllowedIP>>(iter: I) -> Self {
        let mut allowed_ips: AllowedIps<()> = Default::default();

        for ip in iter {
            allowed_ips.insert(ip.addr, ip.cidr as usize, ());
        }

        allowed_ips
    }
}

impl<D> AllowedIps<D> {
    pub fn clear(&mut self) {
        self.v4 = None;
        self.v6 = None;
    }

    pub fn insert(&mut self, key: IpAddr, cidr: usize, data: D) -> Option<D> {
        match key {
            IpAddr::V4(addr) => {
                assert!(cidr <= 32);
                insert32(&mut self.v4, u32::from(addr), cidr, data)
            }
            IpAddr::V6(addr) => {
                assert!(cidr <= 128);
                insert128(&mut self.v6, u128::from(addr), cidr, data)
            }
        }
    }

    pub fn find(&self, key: IpAddr) -> Option<&D> {
        match key {
            IpAddr::V4(addr) => find32(&self.v4, u32::from(addr)),
            IpAddr::V6(addr) => find128(&self.v6, u128::from(addr)),
        }
    }

    pub fn remove(&mut self, predicate: &Fn(&D) -> bool) {
        remove32(&mut self.v4, predicate);
        remove128(&mut self.v6, predicate);
    }

    pub fn iter(&self) -> Iter<D> {
        Iter::new(&self.v4, &self.v6)
    }
}

/// This is a iterator that progresses through an in-order traversal.
pub struct Iter<'a, D: 'a> {
    iter_v4: Iter32<'a, D>,
    iter_v6: Iter128<'a, D>,
}

impl<'a, D> Iter<'a, D> {
    fn new(v4: &'a Option<Node32<D>>, v6: &'a Option<Node128<D>>) -> Self {
        Iter {
            iter_v4: Iter32::new(v4),
            iter_v6: Iter128::new(v6),
        }
    }
}

impl<'a, D> Iterator for Iter<'a, D> {
    type Item = (&'a D, IpAddr, usize);
    fn next(&mut self) -> Option<Self::Item> {
        let try_v4 = self.iter_v4.next();

        if let Some((data, addr, cidr)) = try_v4 {
            return Some((data, IpAddr::V4(Ipv4Addr::from(addr)), cidr));
        }

        let try_v6 = self.iter_v6.next();
        if let Some((data, addr, cidr)) = try_v6 {
            return Some((data, IpAddr::V6(Ipv6Addr::from(addr)), cidr));
        }
        None
    }
}

macro_rules! mask_key {
    ($key: expr, $bits: expr, $size: expr, $mask: expr) => {
        if $bits > 0 {
            $key & ($mask << ($size - $bits))
        } else {
            0
        };
    };
}

macro_rules! build_node {
    ($name: ident, $find: ident, $remove: ident, $insert: ident, $keyt: ty) => {
        #[derive(Debug)]
        enum $name<D> {
            Node {
                cur_key: $keyt,               // The part of the key stored in this node
                cur_bits: usize,              // How many bits of the key to store
                data: Option<D>,              // Optional data for this node
                left: Box<Option<$name<D>>>,  // Left subtree, go there if next bit of key is 0
                right: Box<Option<$name<D>>>, // Right subtree, go there if next bit of key is 1
            },
            Leaf($keyt, usize, D), // Leaf node, keyt: part of the key to match, usize: how much to match, D: data on match
        }

        fn $find<D>(node: &Option<$name<D>>, key: $keyt) -> Option<&D> {
            const BM1: usize = std::mem::size_of::<$keyt>() * 8 - 1; // Bits in key minus one

            match node {
                None => None,
                Some($name::Leaf(cur_key, cur_bits, cur_data)) => {
                    let shared_bits = (cur_key ^ key).leading_zeros() as usize;
                    if shared_bits >= *cur_bits {
                        Some(cur_data)
                    } else {
                        None
                    }
                }
                Some($name::Node {
                    cur_key,
                    cur_bits,
                    data,
                    left,
                    right,
                }) => {
                    let ret = if *cur_bits == 0 {
                        if key >> BM1 == 0 {
                            $find(left, key << 1)
                        } else {
                            $find(right, key << 1)
                        }
                    } else {
                        let shared_bits = (cur_key ^ key).leading_zeros() as usize;
                        if shared_bits >= *cur_bits {
                            if (key >> (BM1 - *cur_bits)) & 1 == 0 {
                                $find(left, key.checked_shl((*cur_bits + 1) as _).unwrap_or(0))
                            } else {
                                $find(right, key.checked_shl((*cur_bits + 1) as _).unwrap_or(0))
                            }
                        } else {
                            return None;
                        }
                    };
                    ret.or(data.as_ref())
                }
            }
        }

        fn $remove<D>(node: &mut Option<$name<D>>, predicate: &Fn(&D) -> bool) {
            match node {
                None => return,
                Some($name::Node {
                    ref mut left,
                    ref mut right,
                    ref mut data,
                    ..
                }) => {
                    $remove(left, predicate);
                    $remove(right, predicate);

                    if let Some(cur_data) = data {
                        if !predicate(cur_data) {
                            return;
                        }
                    }
                    // If we got here the Node contains the data we want to remove
                    *data = None;
                    return;
                }
                Some($name::Leaf(_, _, ref cur_data)) => {
                    if !predicate(cur_data) {
                        return;
                    }
                }
            }
            // If we got here the Leaf contains the data we want to remove
            *node = None
        }

        /// Attempt to insert data with a given key and mask
        /// If a key already exists, we replace it and return the old data
        fn $insert<D>(node: &mut Option<$name<D>>, key: $keyt, bits: usize, data: D) -> Option<D> {
            const BITS: usize = std::mem::size_of::<$keyt>() * 8; // Bits in key
            const BM1: usize = BITS - 1; // Bits in key minus one
            const ZERO: $keyt = 0;
            let mask: $keyt = ZERO.wrapping_sub(1);

            let cur_node = node.take();
            match cur_node {
                None => {
                    // We reached a vacant spot, this is easy, just create a new Leaf in place
                    let masked_key = mask_key!(key, bits, BITS, mask);
                    *node = Some($name::Leaf(masked_key, bits, data));
                    return None;
                }
                Some($name::Leaf(cur_key, cur_bits, cur_data)) => {
                    // We got to a Leaf, this is still pretty simple

                    // First find out the number of equal bits between cur_key (the key stored in the node) and key (the key we want to insert)
                    let shared_bits =
                        min((cur_key ^ key).leading_zeros() as _, min(bits, cur_bits));

                    if shared_bits == cur_bits && bits == cur_bits {
                        // The new key matches this Leaf exactly, so we replace it
                        *node = Some($name::Leaf(cur_key, cur_bits, data)); // Keep current key and bits, but store the new data instead
                        return Some(cur_data);
                    }

                    let shared_key = mask_key!(cur_key, shared_bits, BITS, mask); // Mask the correct bits of the key

                    if shared_bits == bits {
                        // The new key is shorter than the current Leaf, we create a Node
                        // The Node will contain the new data, and will fork to the existing Leaf as needed
                        let diff_bit = ((cur_key >> (BM1 - shared_bits)) & 1) == 1; // The next bit

                        // Create new Leaf from old Leaf
                        let old_bits = cur_bits - shared_bits - 1;
                        let old_key = mask_key!(cur_key << (shared_bits + 1), old_bits, BITS, mask);
                        let old_node = Some($name::Leaf(old_key, old_bits, cur_data));
                        // Decide if the previous Leaf will go left or right
                        let (left, right) = if diff_bit {
                            (None, old_node)
                        } else {
                            (old_node, None)
                        };
                        // Create new Node
                        *node = Some($name::Node {
                            cur_key: shared_key,
                            cur_bits: shared_bits,
                            data: Some(data),
                            left: Box::new(left),
                            right: Box::new(right),
                        });
                        return None;
                    }

                    if shared_bits == cur_bits {
                        // The new key is longer than the current Leaf, we create a Node
                        // The Node will hold the current Leaf data as its data, and will fork to a new Leaf
                        let diff_bit = (key >> (BM1 - shared_bits)) & 1 == 1; // The next bit

                        // Create new Leaf with new key and data
                        let new_bits = bits - shared_bits - 1;
                        let new_key = mask_key!(key << (shared_bits + 1), new_bits, BITS, mask);
                        let new_node = Some($name::Leaf(new_key, new_bits, data));
                        // Decide if the new Leaf will go left or right
                        let (left, right) = if diff_bit {
                            (None, new_node)
                        } else {
                            (new_node, None)
                        };

                        *node = Some($name::Node {
                            cur_key: shared_key,
                            cur_bits: shared_bits,
                            data: Some(cur_data),
                            left: Box::new(left),
                            right: Box::new(right),
                        });
                        return None;
                    }

                    // The new entry and the old entry diverge in the middle, we need to split at a new Node
                    let diff_bit = (key >> (BM1 - shared_bits)) & 1 == 1; // The next bit of the new key

                    // Create new Leaf with new key and data
                    let new_bits = bits - shared_bits - 1;
                    let new_key = mask_key!(key << (shared_bits + 1), new_bits, BITS, mask);
                    let new_node = $name::Leaf(new_key, new_bits, data);
                    // Create new Leaf from old Leaf
                    let old_bits = cur_bits - shared_bits - 1;
                    let old_key = mask_key!(cur_key << (shared_bits + 1), old_bits, BITS, mask);
                    let old_node = $name::Leaf(old_key, old_bits, cur_data);
                    // Decide if the Leaf with new key/data will go left or right
                    let (left, right) = if diff_bit {
                        (old_node, new_node)
                    } else {
                        (new_node, old_node)
                    };

                    *node = Some($name::Node {
                        cur_key: shared_key,
                        cur_bits: shared_bits,
                        data: None,
                        left: Box::new(Some(left)),
                        right: Box::new(Some(right)),
                    });
                    return None;
                }
                Some($name::Node {
                    cur_key,
                    cur_bits,
                    data: cur_data,
                    mut left,
                    mut right,
                }) => {
                    // We are at an existing Node, there are a few scenarios that can happen:
                    let shared_bits =
                        min((cur_key ^ key).leading_zeros() as _, min(bits, cur_bits));

                    if shared_bits == bits && shared_bits == cur_bits {
                        // The new key matches this Node exactly, so we replace it
                        *node = Some($name::Node {
                            cur_key,
                            cur_bits,
                            data: Some(data),
                            left,
                            right,
                        });
                        return cur_data;
                    }

                    let shared_key = mask_key!(cur_key, shared_bits, BITS, mask); // Mask the correct bits of the key

                    if shared_bits == bits {
                        // The new key is shorter than the current Node, we create a split Node
                        // The split Node will contain the new data, and will fork to the existing Node as needed
                        let diff_bit = ((cur_key >> (BM1 - shared_bits)) & 1) == 1; // The next bit

                        // Create new Leaf from old Leaf
                        let old_bits = cur_bits - shared_bits - 1;
                        let old_key = mask_key!(cur_key << (shared_bits + 1), old_bits, BITS, mask);
                        let old_node = Some($name::Node {
                            cur_key: old_key,
                            cur_bits: old_bits,
                            data: cur_data,
                            left,
                            right,
                        });
                        // Decide if the previous Leaf will go left or right
                        let (left, right) = if diff_bit {
                            (None, old_node)
                        } else {
                            (old_node, None)
                        };
                        // Create new Node
                        *node = Some($name::Node {
                            cur_key: shared_key,
                            cur_bits: shared_bits,
                            data: Some(data),
                            left: Box::new(left),
                            right: Box::new(right),
                        });
                        return None;
                    }

                    if shared_bits == cur_bits {
                        // We matched all the bits, but still have some left, insert into a subtree
                        let next_bit = (key >> (BM1 - shared_bits)) & 1 == 1; // Decide if traverse left or right
                        {
                            let dir = if next_bit { &mut right } else { &mut left };
                            $insert(dir, key << (shared_bits + 1), bits - shared_bits - 1, data);
                        }
                        // The node is unchanged
                        *node = Some($name::Node {
                            cur_key,
                            cur_bits,
                            data: cur_data,
                            left,
                            right,
                        });
                        return None;
                    }

                    // The new entry and the old entry diverge in the middle, we need to split at a new Node   let shared_key = mask_key!(cur_key, shared_bits, BITS, mask);
                    let diff_bit = (key >> (BM1 - shared_bits)) & 1 == 1; // The next bit of the new key

                    let new_bits = bits - shared_bits - 1;
                    let old_bits = cur_bits - shared_bits - 1;
                    let new_key = mask_key!(key << (shared_bits + 1), new_bits, BITS, mask);
                    let old_key = mask_key!(cur_key << (shared_bits + 1), old_bits, BITS, mask);

                    let new_node = $name::Leaf(new_key, new_bits, data);
                    let old_node = $name::Node {
                        cur_key: old_key,
                        cur_bits: old_bits,
                        data: cur_data,
                        left,
                        right,
                    };

                    let (left, right) = if diff_bit {
                        (old_node, new_node)
                    } else {
                        (new_node, old_node)
                    };

                    *node = Some($name::Node {
                        cur_key: shared_key,
                        cur_bits: shared_bits,
                        data: None,
                        left: Box::new(Some(left)),
                        right: Box::new(Some(right)),
                    });

                    return None;
                }
            }
        }
    };
}

macro_rules! build_iter {
    ($name: ident, $node: ident, $keyt: ty) => {
        /// This is a iterator that progresses through a DFS traversal.
        pub struct $name<'a, D: 'a> {
            stack: Vec<&'a Option<$node<D>>>,
            key_hlp: Vec<($keyt, usize)>,
        }

        impl<'a, D> $name<'a, D> {
            fn new(root: &'a Option<$node<D>>) -> Self {
                $name {
                    stack: vec![root],
                    key_hlp: vec![(0, 0)],
                }
            }
        }

        impl<'a, D> Iterator for $name<'a, D> {
            type Item = (&'a D, $keyt, usize);
            fn next(&mut self) -> Option<Self::Item> {
                const BITS: usize = std::mem::size_of::<$keyt>() * 8; // Bits in key
                const BM1: usize = BITS - 1; // Bits in key minus one

                while !self.stack.is_empty() {
                    let node = self.stack.pop().unwrap();
                    match node {
                        None => {
                            self.key_hlp.pop();
                        }
                        Some($node::Leaf(key, bits, data)) => {
                            let (cur_key, cur_bits) = self.key_hlp.pop().unwrap();
                            return Some((data, cur_key ^ (key >> cur_bits), cur_bits + bits));
                        }
                        Some($node::Node {
                            cur_key,
                            cur_bits,
                            data,
                            ref left,
                            ref right,
                        }) => {
                            let (key, mut bits) = self.key_hlp.pop().unwrap();
                            let cur_key = key ^ (cur_key >> bits);
                            bits += cur_bits;

                            self.stack.push(right);
                            self.stack.push(left);

                            self.key_hlp.push((cur_key ^ (1 << (BM1 - bits)), bits + 1));
                            self.key_hlp.push((cur_key, bits + 1));

                            if let Some(ref data) = data {
                                return Some((data, cur_key, bits));
                            }
                        }
                    }
                }
                None
            }
        }
    };
}

build_node!(Node32, find32, remove32, insert32, u32);
build_node!(Node128, find128, remove128, insert128, u128);

build_iter!(Iter32, Node32, u32);
build_iter!(Iter128, Node128, u128);

#[cfg(test)]
mod tests {
    use super::*;

    fn build_allowed_ips() -> AllowedIps<char> {
        let mut map: AllowedIps<char> = Default::default();
        map.insert(IpAddr::from([127, 0, 0, 1]), 32, '1');
        map.insert(IpAddr::from([45, 25, 15, 1]), 30, '6');
        map.insert(IpAddr::from([127, 0, 15, 1]), 16, '2');
        map.insert(IpAddr::from([127, 1, 15, 1]), 24, '3');
        map.insert(IpAddr::from([255, 1, 15, 1]), 24, '4');
        map.insert(IpAddr::from([60, 25, 15, 1]), 32, '5');
        map.insert(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128, '7');
        map
    }

    #[test]
    fn test_allowed_ips_insert_find() {
        let map = build_allowed_ips();
        assert_eq!(map.find(IpAddr::from([127, 0, 0, 1])), Some(&'1'));
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 255, 255])), None);
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(IpAddr::from([255, 1, 15, 2])), Some(&'4'));
        assert_eq!(map.find(IpAddr::from([60, 25, 15, 1])), Some(&'5'));
        assert_eq!(map.find(IpAddr::from([20, 0, 0, 100])), None);
        assert_eq!(
            map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0])),
            Some(&'7')
        );
        assert_eq!(map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 1])), None);
        assert_eq!(map.find(IpAddr::from([45, 25, 15, 1])), Some(&'6'));
    }

    #[test]
    fn test_allowed_ips_remove() {
        let mut map = build_allowed_ips();
        map.remove(&|c| *c == '5' || *c == '1' || *c == '7');

        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'6', IpAddr::from([45, 25, 15, 0]), 30))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', IpAddr::from([127, 0, 0, 0]), 16))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', IpAddr::from([127, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'4', IpAddr::from([255, 1, 15, 0]), 24))
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn test_allowed_ips_iter() {
        let map = build_allowed_ips();
        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'6', IpAddr::from([45, 25, 15, 0]), 30))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'5', IpAddr::from([60, 25, 15, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', IpAddr::from([127, 0, 0, 0]), 16))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'1', IpAddr::from([127, 0, 0, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', IpAddr::from([127, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'4', IpAddr::from([255, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'7', IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128))
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn test_allowed_ips_v4_kernel_compatibility() {
        // Test case from wireguard-go
        let mut map: AllowedIps<char> = Default::default();

        map.insert(IpAddr::from([192, 168, 4, 0]), 24, 'a');
        map.insert(IpAddr::from([192, 168, 4, 4]), 32, 'b');
        map.insert(IpAddr::from([192, 168, 0, 0]), 16, 'c');
        map.insert(IpAddr::from([192, 95, 5, 64]), 27, 'd');
        map.insert(IpAddr::from([192, 95, 5, 65]), 27, 'c');
        map.insert(IpAddr::from([0, 0, 0, 0]), 0, 'e');
        map.insert(IpAddr::from([64, 15, 112, 0]), 20, 'g');
        map.insert(IpAddr::from([64, 15, 123, 211]), 25, 'h');
        map.insert(IpAddr::from([10, 0, 0, 0]), 25, 'a');
        map.insert(IpAddr::from([10, 0, 0, 128]), 25, 'b');
        map.insert(IpAddr::from([10, 1, 0, 0]), 30, 'a');
        map.insert(IpAddr::from([10, 1, 0, 4]), 30, 'b');
        map.insert(IpAddr::from([10, 1, 0, 8]), 29, 'c');
        map.insert(IpAddr::from([10, 1, 0, 16]), 29, 'd');

        assert_eq!(Some(&'a'), map.find(IpAddr::from([192, 168, 4, 20])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([192, 168, 4, 0])));
        assert_eq!(Some(&'b'), map.find(IpAddr::from([192, 168, 4, 4])));
        assert_eq!(Some(&'c'), map.find(IpAddr::from([192, 168, 200, 182])));
        assert_eq!(Some(&'c'), map.find(IpAddr::from([192, 95, 5, 68])));
        assert_eq!(Some(&'e'), map.find(IpAddr::from([192, 95, 5, 96])));
        assert_eq!(Some(&'g'), map.find(IpAddr::from([64, 15, 116, 26])));
        assert_eq!(Some(&'g'), map.find(IpAddr::from([64, 15, 127, 3])));

        map.insert(IpAddr::from([1, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([64, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([128, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([192, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([255, 0, 0, 0]), 32, 'a');

        assert_eq!(Some(&'a'), map.find(IpAddr::from([1, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([64, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([128, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([192, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([255, 0, 0, 0])));

        map.remove(&|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(IpAddr::from([1, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([64, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([128, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([192, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([255, 0, 0, 0])));

        map.clear();

        map.insert(IpAddr::from([192, 168, 0, 0]), 16, 'a');
        map.insert(IpAddr::from([192, 168, 0, 0]), 24, 'a');

        map.remove(&|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(IpAddr::from([192, 168, 0, 1])));
    }

    #[test]
    fn test_allowed_ips_v6_kernel_compatibility() {
        // Test case from wireguard-go
        let mut map: AllowedIps<char> = Default::default();

        map.insert(
            IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0xc05f, 0x0543,
            ]),
            128,
            'd',
        );
        map.insert(
            IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            64,
            'c',
        );
        map.insert(
            IpAddr::from([
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            0,
            'e',
        );
        map.insert(
            IpAddr::from([
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            0,
            'f',
        );
        map.insert(
            IpAddr::from([
                0x2404, 0x6800, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            32,
            'g',
        );
        map.insert(
            IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef,
            ]),
            64,
            'h',
        );
        map.insert(
            IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef,
            ]),
            128,
            'a',
        );
        map.insert(
            IpAddr::from([
                0x2444, 0x6800, 0x40e4, 0x0800, 0xdeae, 0xbeef, 0x0def, 0xbeef,
            ]),
            128,
            'c',
        );
        map.insert(
            IpAddr::from([
                0x2444, 0x6800, 0xf0e4, 0x0800, 0xeeae, 0xbeef, 0x0000, 0x0000,
            ]),
            98,
            'b',
        );

        assert_eq!(
            Some(&'d'),
            map.find(IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0xc05f, 0x0543
            ]))
        );
        assert_eq!(
            Some(&'c'),
            map.find(IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0, 0, 0xc02e, 0x01ee
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(IpAddr::from([0x2607, 0x5300, 0x6000, 0x6b01, 0, 0, 0, 0]))
        );
        assert_eq!(
            Some(&'g'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0806, 0, 0, 0, 0x1006
            ]))
        );
        assert_eq!(
            Some(&'g'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(IpAddr::from([
                0x2404, 0x67ff, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(IpAddr::from([
                0x2404, 0x6801, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(IpAddr::from([0x2404, 0x6800, 0x4004, 0x0800, 0, 0, 0, 0]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0x1010, 0x1010, 0x1010, 0x1010
            ]))
        );
        assert_eq!(
            Some(&'a'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef
            ]))
        );
    }
}
