use std::net::*;

pub struct AllowedIps<D> {
    v4: Option<Node32<D>>,
    v6: Option<Node128<D>>,
}

impl<D> Default for AllowedIps<D> {
    fn default() -> Self {
        Self { v4: None, v6: None }
    }
}

impl<D> AllowedIps<D> {
    pub fn clear(&mut self) {
        self.v4 = None;
        self.v6 = None;
    }

    pub fn insert(&mut self, key: IpAddr, cidr: usize, data: D) {
        match key {
            IpAddr::V4(addr) => {
                assert!(cidr <= 32);
                insert32(&mut self.v4, u32::from(addr), cidr, data);
            }
            IpAddr::V6(addr) => {
                assert!(cidr <= 128);
                insert128(&mut self.v6, u128::from(addr), cidr, data);
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

    pub fn iter<'a>(&'a self) -> Iter<'a, D> {
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
        enum $name<D> {
            Node($keyt, usize, Box<Option<$name<D>>>, Box<Option<$name<D>>>),
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
                Some($name::Node(cur_key, cur_bits, left, right)) => {
                    if *cur_bits == 0 {
                        if key >> BM1 == 0 {
                            $find(left, key << 1)
                        } else {
                            $find(right, key << 1)
                        }
                    } else {
                        let shared_bits = (cur_key ^ key).leading_zeros() as usize;
                        if shared_bits >= *cur_bits {
                            if (key >> (BM1 - *cur_bits)) & 1 == 0 {
                                $find(left, key << (*cur_bits + 1))
                            } else {
                                $find(right, key << (*cur_bits + 1))
                            }
                        } else {
                            None
                        }
                    }
                }
            }
        }

        fn $remove<D>(node: &mut Option<$name<D>>, predicate: &Fn(&D) -> bool) {
            match node {
                None => return,
                Some($name::Node(_, _, ref mut left, ref mut right)) => {
                    $remove(left, predicate);
                    $remove(right, predicate);
                    return;
                }
                Some($name::Leaf(_, _, ref cur_data)) => {
                    if !predicate(cur_data) {
                        return;
                    }
                }
            }
            // If we got here the node contains the data we want to remove
            *node = None
        }

        fn $insert<D>(node: &mut Option<$name<D>>, key: $keyt, bits: usize, data: D) {
            const BITS: usize = std::mem::size_of::<$keyt>() * 8; // Bits in key
            const BM1: usize = BITS - 1; // Bits in key minus one
            const ZERO: $keyt = 0;
            let mask: $keyt = ZERO.wrapping_sub(1);

            let cur_node = node.take();
            match cur_node {
                None => {
                    let masked_key = mask_key!(key, bits, BITS, mask);
                    *node = Some($name::Leaf(masked_key, bits, data));
                    return;
                }
                Some($name::Leaf(cur_key, cur_bits, cur_data)) => {
                    let shared_bits =
                        std::cmp::min((cur_key ^ key).leading_zeros() as usize, cur_bits);

                    if shared_bits >= bits || shared_bits >= cur_bits {
                        // The new key contains this leaf (i.e. smaller cidr or same key)
                        let shared_key = mask_key!(key, bits, BITS, mask);
                        *node = Some($name::Leaf(shared_key, bits, data));
                        return;
                    }

                    // The new entry and the old entry diverge, need to split
                    let shared_key = mask_key!(cur_key, shared_bits, BITS, mask);
                    let diff_bit = (key >> (BM1 - shared_bits)) & 1 == 1; // Decide if the new key will go left or right
                    let new_bits = bits - shared_bits - 1;
                    let old_bits = cur_bits - shared_bits - 1;
                    let new_key = mask_key!(key << (shared_bits + 1), new_bits, BITS, mask);
                    let old_key = mask_key!(cur_key << (shared_bits + 1), old_bits, BITS, mask);

                    let new_node = $name::Leaf(new_key, new_bits, data);
                    let old_node = $name::Leaf(old_key, old_bits, cur_data);

                    let (left, right) = match diff_bit {
                        true => (old_node, new_node),
                        false => (new_node, old_node),
                    };

                    *node = Some($name::Node(
                        shared_key,
                        shared_bits,
                        Box::new(Some(left)),
                        Box::new(Some(right)),
                    ));

                    return;
                }
                Some($name::Node(cur_key, cur_bits, mut left, mut right)) => {
                    let shared_bits =
                        std::cmp::min((cur_key ^ key).leading_zeros() as usize, cur_bits);

                    if shared_bits >= bits {
                        // The new key contains this node (i.e. smaller cidr)
                        let masked_key = mask_key!(key, bits, BITS, mask);
                        *node = Some($name::Leaf(masked_key, bits, data));
                        return;
                    }

                    if shared_bits >= cur_bits {
                        // We matched the node key fully, and need to traverse further
                        let next_bit = (key >> (BM1 - shared_bits)) & 1 == 1; // Decide if traverse left or right
                        {
                            let dir = match next_bit {
                                false => &mut left,
                                true => &mut right,
                            };
                            $insert(dir, key << (shared_bits + 1), bits - shared_bits - 1, data);
                        }
                        *node = Some($name::Node(cur_key, cur_bits, left, right));
                        return;
                    }

                    // The new entry and the old entry diverge, need to split
                    let shared_key = mask_key!(cur_key, shared_bits, BITS, mask);
                    let diff_bit = (key >> (BM1 - shared_bits)) & 1 == 1; // Decide if the new key will go left or right
                    let new_bits = bits - shared_bits - 1;
                    let old_bits = cur_bits - shared_bits - 1;
                    let new_key = mask_key!(key << (shared_bits + 1), new_bits, BITS, mask);
                    let old_key = mask_key!(cur_key << (shared_bits + 1), old_bits, BITS, mask);

                    let new_node = $name::Leaf(new_key, new_bits, data);
                    let old_node = $name::Node(old_key, old_bits, left, right);

                    let (left, right) = match diff_bit {
                        true => (old_node, new_node),
                        false => (new_node, old_node),
                    };

                    *node = Some($name::Node(
                        shared_key,
                        shared_bits,
                        Box::new(Some(left)),
                        Box::new(Some(right)),
                    ));
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
                        Some($node::Node(key, bits, ref left, ref right)) => {
                            let (mut cur_key, mut cur_bits) = self.key_hlp.pop().unwrap();
                            cur_key ^= key >> cur_bits;
                            cur_bits += bits;

                            self.stack.push(right);
                            self.stack.push(left);

                            self.key_hlp
                                .push((cur_key ^ (1 << (BM1 - cur_bits)), cur_bits + 1));
                            self.key_hlp.push((cur_key, cur_bits + 1));
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

    #[test]
    fn test_allowed_ips() {
        let mut map: AllowedIps<String> = Default::default();
        map.insert(IpAddr::from([127, 0, 0, 1]), 32, "peer1".to_owned());
        assert_eq!(map.find(IpAddr::from([127, 0, 0, 1])).unwrap(), "peer1");
        map.insert(IpAddr::from([45, 25, 15, 1]), 30, "peer6".to_owned());
        map.insert(IpAddr::from([127, 0, 15, 1]), 16, "peer2".to_owned());
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])).unwrap(), "peer2");
        assert_eq!(map.find(IpAddr::from([127, 1, 255, 255])), None);
        map.insert(IpAddr::from([127, 1, 15, 1]), 24, "peer3".to_owned());
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])).unwrap(), "peer2");
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])).unwrap(), "peer3");
        map.insert(IpAddr::from([255, 1, 15, 1]), 24, "peer4".to_owned());
        map.insert(IpAddr::from([60, 25, 15, 1]), 32, "peer5".to_owned());
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])).unwrap(), "peer2");
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])).unwrap(), "peer3");
        assert_eq!(map.find(IpAddr::from([255, 1, 15, 2])).unwrap(), "peer4");
        assert_eq!(map.find(IpAddr::from([60, 25, 15, 1])).unwrap(), "peer5");
        assert_eq!(map.find(IpAddr::from([20, 0, 0, 100])), None);

        map.insert(
            IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]),
            128,
            "peer7".to_owned(),
        );

        assert_eq!(
            map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0])),
            Some(&"peer7".to_owned())
        );
        assert_eq!(map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 1])), None);

        {
            let mut map_iter = map.iter();
            assert_eq!(map_iter.next().unwrap().0, "peer6");
            assert_eq!(map_iter.next().unwrap().0, "peer5");
            assert_eq!(map_iter.next().unwrap().0, "peer2");
            assert_eq!(map_iter.next().unwrap().0, "peer3");
            assert_eq!(map_iter.next().unwrap().0, "peer4");
            assert_eq!(map_iter.next().unwrap().0, "peer7");
            assert_eq!(map_iter.next(), None);
        }
        {
            let mut map_iter = map.iter();
            assert_eq!(map_iter.next().unwrap().1, IpAddr::from([45, 25, 15, 0]));
            assert_eq!(map_iter.next().unwrap().1, IpAddr::from([60, 25, 15, 1]));
            assert_eq!(map_iter.next().unwrap().1, IpAddr::from([127, 0, 0, 0]));
            assert_eq!(map_iter.next().unwrap().1, IpAddr::from([127, 1, 15, 0]));
            assert_eq!(map_iter.next().unwrap().1, IpAddr::from([255, 1, 15, 0]));
            assert_eq!(
                map_iter.next().unwrap().1,
                IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0])
            );
        }

        map.remove(&|s: &String| s == "peer5");
        assert_eq!(map.find(IpAddr::from([60, 25, 15, 1])), None);

        {
            let mut map_iter = map.iter();
            assert_eq!(map_iter.next().unwrap().0, "peer6");
            assert_eq!(map_iter.next().unwrap().0, "peer2");
            assert_eq!(map_iter.next().unwrap().0, "peer3");
            assert_eq!(map_iter.next().unwrap().0, "peer4");
            assert_eq!(map_iter.next().unwrap().0, "peer7");
            assert_eq!(map_iter.next(), None);
        }
    }
}
