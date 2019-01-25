pub struct IPv4Map<K: Into<u32>, D> {
    root: Option<Node32<D>>,
    phantom: std::marker::PhantomData<K>,
}

pub struct IPv6Map<K: Into<u128>, D> {
    root: Option<Node128<D>>,
    phantom: std::marker::PhantomData<K>,
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
    ($name: ident, $find: ident, $insert: ident, $keyt: ty) => {
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

                    if shared_bits >= bits {
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

// Would be better to implement with generics, but leading_zeros is not a trait
build_node!(Node32, find32, insert32, u32);
build_node!(Node128, find128, insert128, u128);

/// This is a generator that progresses through an in-order traversal.
pub struct Iter<'a, D: 'a> {
    stack: Vec<&'a Option<Node32<D>>>,
    key_hlp: Vec<(u32, usize)>,
}

impl<'a, D> Iter<'a, D> {
    fn new(root: &'a Option<Node32<D>>) -> Self {
        Iter {
            stack: vec![root],
            key_hlp: vec![(0u32, 0usize)],
        }
    }
}

impl<'a, D> Iterator for Iter<'a, D> {
    type Item = (&'a D, u32, usize);
    fn next(&mut self) -> Option<Self::Item> {
        while !self.stack.is_empty() {
            let node = self.stack.pop().unwrap();
            match node {
                None => return None,
                Some(Node32::Leaf(key, bits, data)) => {
                    let (cur_key, cur_bits) = self.key_hlp.pop().unwrap();
                    return Some((data, cur_key ^ (key >> cur_bits), cur_bits + bits));
                }
                Some(Node32::Node(key, bits, ref left, ref right)) => {
                    let (mut cur_key, mut cur_bits) = self.key_hlp.pop().unwrap();
                    cur_key ^= key >> cur_bits;
                    cur_bits += bits;

                    self.stack.push(right);
                    self.stack.push(left);

                    self.key_hlp
                        .push((cur_key ^ (1 << (31 - cur_bits)), cur_bits + 1));
                    self.key_hlp.push((cur_key, cur_bits + 1));
                }
            }
        }
        None
    }
}

impl<K, D> Default for IPv4Map<K, D>
where
    u32: From<K>,
{
    fn default() -> Self {
        Self {
            root: None,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<K: Into<u32>, D> IPv4Map<K, D> {
    pub fn clear(&mut self) {
        self.root = None;
    }

    pub fn insert(&mut self, key: K, bits: usize, data: D) {
        assert!(bits <= 32);
        let key: u32 = K::into(key);
        insert32(&mut self.root, key, bits, data)
    }

    pub fn find(&self, key: K) -> Option<&D> {
        let key: u32 = K::into(key);
        find32(&self.root, key)
    }

    pub fn iter<'a>(&'a self) -> Iter<'a, D> {
        Iter::new(&self.root)
    }
}

impl<K, D> Default for IPv6Map<K, D>
where
    u128: From<K>,
{
    fn default() -> Self {
        Self {
            root: None,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<K: Into<u128>, D> IPv6Map<K, D> {
    pub fn clear(&mut self) {
        self.root = None;
    }

    pub fn insert(&mut self, key: K, bits: usize, data: D) {
        assert!(bits <= 128);
        let key: u128 = K::into(key);
        insert128(&mut self.root, key, bits, data)
    }

    pub fn find(&self, key: K) -> Option<&D> {
        let key: u128 = K::into(key);
        find128(&self.root, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::*;

    #[test]
    fn test_ip_map_v4() {
        let mut map: IPv4Map<Ipv4Addr, String> = Default::default();

        map.insert(Ipv4Addr::new(127, 0, 0, 1), 32, "peer1".to_owned());
        assert_eq!(map.find(Ipv4Addr::new(127, 0, 0, 1)).unwrap(), "peer1");
        map.insert(Ipv4Addr::new(45, 25, 15, 1), 30, "peer6".to_owned());
        map.insert(Ipv4Addr::new(127, 0, 15, 1), 16, "peer2".to_owned());
        assert_eq!(map.find(Ipv4Addr::new(127, 0, 255, 255)).unwrap(), "peer2");
        assert_eq!(map.find(Ipv4Addr::new(127, 1, 255, 255)), None);
        map.insert(Ipv4Addr::new(127, 1, 15, 1), 24, "peer3".to_owned());
        assert_eq!(map.find(Ipv4Addr::new(127, 0, 255, 255)).unwrap(), "peer2");
        assert_eq!(map.find(Ipv4Addr::new(127, 1, 15, 255)).unwrap(), "peer3");
        map.insert(Ipv4Addr::new(255, 1, 15, 1), 24, "peer4".to_owned());
        map.insert(Ipv4Addr::new(60, 25, 15, 1), 32, "peer5".to_owned());
        assert_eq!(map.find(Ipv4Addr::new(127, 0, 255, 255)).unwrap(), "peer2");
        assert_eq!(map.find(Ipv4Addr::new(127, 1, 15, 255)).unwrap(), "peer3");
        assert_eq!(map.find(Ipv4Addr::new(255, 1, 15, 2)).unwrap(), "peer4");
        assert_eq!(map.find(Ipv4Addr::new(60, 25, 15, 1)).unwrap(), "peer5");
        assert_eq!(map.find(Ipv4Addr::new(20, 0, 0, 100)), None);

        let mut map_iter = map.iter();
        assert_eq!(map_iter.next().unwrap().0, "peer6");
        assert_eq!(map_iter.next().unwrap().0, "peer5");
        assert_eq!(map_iter.next().unwrap().0, "peer2");
        assert_eq!(map_iter.next().unwrap().0, "peer3");
        assert_eq!(map_iter.next().unwrap().0, "peer4");
        assert_eq!(map_iter.next(), None);

        let mut map_iter = map.iter();
        assert_eq!(
            Ipv4Addr::from(map_iter.next().unwrap().1),
            Ipv4Addr::new(45, 25, 15, 0)
        );
        assert_eq!(
            Ipv4Addr::from(map_iter.next().unwrap().1),
            Ipv4Addr::new(60, 25, 15, 1)
        );
        assert_eq!(
            Ipv4Addr::from(map_iter.next().unwrap().1),
            Ipv4Addr::new(127, 0, 0, 0)
        );
        assert_eq!(
            Ipv4Addr::from(map_iter.next().unwrap().1),
            Ipv4Addr::new(127, 1, 15, 0)
        );
        assert_eq!(
            Ipv4Addr::from(map_iter.next().unwrap().1),
            Ipv4Addr::new(255, 1, 15, 0)
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn test_ip_map_v6() {
        let mut map: IPv6Map<Ipv6Addr, String> = Default::default();

        map.insert(
            Ipv6Addr::new(65534, 0, 0, 1, 0, 0, 0, 0),
            128,
            "peer1".to_owned(),
        );
        assert_eq!(
            map.find(Ipv6Addr::new(65534, 0, 0, 1, 0, 0, 0, 0)),
            Some(&"peer1".to_owned())
        );
        assert_eq!(map.find(Ipv6Addr::new(65534, 0, 0, 1, 0, 0, 0, 1)), None);
    }

}
