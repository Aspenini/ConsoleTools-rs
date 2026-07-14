//! AVL tree used both for building the on-disc directory layout when
//! creating an image and for capturing the directory tree when rewriting
//! one. The xbox expects directory tables laid out in prefix order of a
//! balanced binary search tree keyed on the uppercased filename, which is
//! exactly what this produces.

use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skew {
    None,
    Left,
    Right,
}

/// What a node represents: a plain file, an empty directory (which still
/// occupies one padding sector on disc), or a directory with contents.
pub enum Subdir {
    File,
    Empty,
    Tree(Box<Node>),
}

/// Root of a (possibly empty) AVL tree.
pub type Tree = Option<Box<Node>>;

pub struct Node {
    pub filename: String,
    pub file_size: u32,
    /// Assigned sector in the output image.
    pub start_sector: u32,
    /// Sector in the source image (rewrite mode only).
    pub old_start_sector: u32,
    /// Byte offset of this node's directory entry within its table.
    pub offset: u32,
    /// Absolute byte offset of the directory table containing this entry.
    pub dir_start: u64,
    pub subdir: Subdir,
    skew: Skew,
    pub left: Tree,
    pub right: Tree,
}

impl Node {
    pub fn new(filename: String) -> Box<Node> {
        Box::new(Node {
            filename,
            file_size: 0,
            start_sector: 0,
            old_start_sector: 0,
            offset: 0,
            dir_start: 0,
            subdir: Subdir::File,
            skew: Skew::None,
            left: None,
            right: None,
        })
    }

    pub fn is_dir(&self) -> bool {
        !matches!(self.subdir, Subdir::File)
    }
}

pub struct DuplicateEntry;

/// Case-insensitive (ASCII) byte-wise comparison — the sort order the xbox
/// uses for directory lookups.
pub fn compare_key(lhs: &str, rhs: &str) -> Ordering {
    lhs.bytes()
        .map(|b| b.to_ascii_uppercase())
        .cmp(rhs.bytes().map(|b| b.to_ascii_uppercase()))
}

/// Insert `node`; returns Ok(true) if the subtree grew in height.
pub fn insert(root: &mut Tree, node: Box<Node>) -> Result<bool, DuplicateEntry> {
    let ord = match root {
        None => {
            *root = Some(node);
            return Ok(true);
        }
        Some(cur) => compare_key(&node.filename, &cur.filename),
    };

    match ord {
        Ordering::Less => {
            let grew = insert(&mut root.as_mut().unwrap().left, node)?;
            Ok(if grew { left_grown(root) } else { false })
        }
        Ordering::Greater => {
            let grew = insert(&mut root.as_mut().unwrap().right, node)?;
            Ok(if grew { right_grown(root) } else { false })
        }
        Ordering::Equal => Err(DuplicateEntry),
    }
}

fn left_grown(root: &mut Tree) -> bool {
    let n = root.as_mut().unwrap();
    match n.skew {
        Skew::Left => {
            if n.left.as_ref().unwrap().skew == Skew::Left {
                n.skew = Skew::None;
                n.left.as_mut().unwrap().skew = Skew::None;
                rotate_right(root);
            } else {
                let (root_skew, left_skew) = {
                    let l = n.left.as_mut().unwrap();
                    let lr = l.right.as_mut().unwrap();
                    let skews = match lr.skew {
                        Skew::Left => (Skew::Right, Skew::None),
                        Skew::Right => (Skew::None, Skew::Left),
                        Skew::None => (Skew::None, Skew::None),
                    };
                    lr.skew = Skew::None;
                    skews
                };
                n.skew = root_skew;
                n.left.as_mut().unwrap().skew = left_skew;
                rotate_left(&mut n.left);
                rotate_right(root);
            }
            false
        }
        Skew::Right => {
            n.skew = Skew::None;
            false
        }
        Skew::None => {
            n.skew = Skew::Left;
            true
        }
    }
}

fn right_grown(root: &mut Tree) -> bool {
    let n = root.as_mut().unwrap();
    match n.skew {
        Skew::Left => {
            n.skew = Skew::None;
            false
        }
        Skew::Right => {
            if n.right.as_ref().unwrap().skew == Skew::Right {
                n.skew = Skew::None;
                n.right.as_mut().unwrap().skew = Skew::None;
                rotate_left(root);
            } else {
                let (root_skew, right_skew) = {
                    let r = n.right.as_mut().unwrap();
                    let rl = r.left.as_mut().unwrap();
                    let skews = match rl.skew {
                        Skew::Left => (Skew::None, Skew::Right),
                        Skew::Right => (Skew::Left, Skew::None),
                        Skew::None => (Skew::None, Skew::None),
                    };
                    rl.skew = Skew::None;
                    skews
                };
                n.skew = root_skew;
                n.right.as_mut().unwrap().skew = right_skew;
                rotate_right(&mut n.right);
                rotate_left(root);
            }
            false
        }
        Skew::None => {
            n.skew = Skew::Right;
            true
        }
    }
}

fn rotate_left(root: &mut Tree) {
    let mut old = root.take().unwrap();
    let mut new = old.right.take().unwrap();
    old.right = new.left.take();
    new.left = Some(old);
    *root = Some(new);
}

fn rotate_right(root: &mut Tree) {
    let mut old = root.take().unwrap();
    let mut new = old.left.take().unwrap();
    old.left = new.right.take();
    new.right = Some(old);
    *root = Some(new);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_order(tree: &Tree, out: &mut Vec<String>) {
        if let Some(n) = tree {
            in_order(&n.left, out);
            out.push(n.filename.clone());
            in_order(&n.right, out);
        }
    }

    fn height(tree: &Tree) -> usize {
        tree.as_ref()
            .map(|n| 1 + height(&n.left).max(height(&n.right)))
            .unwrap_or(0)
    }

    #[test]
    fn sorts_case_insensitively_and_balances() {
        let names = [
            "zeta", "Alpha", "GAMMA", "beta", "mu", "NU", "xi", "pi", "RHO", "delta", "ETA",
            "Iota", "kappa", "LAMBDA", "Omicron", "sigma", "TAU", "upsilon", "Epsilon", "theta",
        ];
        let mut tree: Tree = None;
        for name in names {
            assert!(insert(&mut tree, Node::new(name.to_string())).is_ok());
        }

        let mut got = Vec::new();
        in_order(&tree, &mut got);
        let mut expected: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        expected.sort_by(|a, b| compare_key(a, b));
        assert_eq!(got, expected);

        // 20 nodes: an AVL tree must stay within ~1.44 * log2(n).
        assert!(height(&tree) <= 6, "tree too deep: {}", height(&tree));
    }

    #[test]
    fn rejects_duplicates_ignoring_case() {
        let mut tree: Tree = None;
        assert!(insert(&mut tree, Node::new("Default.xbe".into())).is_ok());
        assert!(insert(&mut tree, Node::new("default.XBE".into())).is_err());
    }
}
