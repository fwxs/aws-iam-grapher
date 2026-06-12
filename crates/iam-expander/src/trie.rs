use std::collections::HashMap;

pub(crate) struct Trie {
    root: TrieNode,
}

struct TrieNode {
    children: HashMap<char, TrieNode>,
    terminal: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            terminal: false,
        }
    }
}

impl Trie {
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
        }
    }

    pub fn insert(&mut self, word: &str) {
        let mut node = &mut self.root;
        for ch in word.chars() {
            node = node.children.entry(ch).or_insert_with(TrieNode::new);
        }
        node.terminal = true;
    }

    /// Returns every stored string that starts with `prefix`.
    pub fn starts_with(&self, prefix: &str) -> Vec<String> {
        let mut node = &self.root;
        for ch in prefix.chars() {
            match node.children.get(&ch) {
                Some(next) => node = next,
                None => return vec![],
            }
        }
        let mut results = Vec::new();
        collect(node, prefix, &mut results);
        results.sort();
        results
    }
}

fn collect(node: &TrieNode, current: &str, results: &mut Vec<String>) {
    if node.terminal {
        results.push(current.to_string());
    }
    for (&ch, child) in &node.children {
        let mut next = current.to_string();
        next.push(ch);
        collect(child, &next, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_prefix_search() {
        let mut trie = Trie::new();
        trie.insert("s3:GetObject");
        trie.insert("s3:GetBucketAcl");
        trie.insert("s3:PutObject");

        let results = trie.starts_with("s3:Get");
        assert_eq!(results.len(), 2);
        assert!(results.contains(&"s3:GetObject".to_string()));
        assert!(results.contains(&"s3:GetBucketAcl".to_string()));
    }

    #[test]
    fn test_no_match_returns_empty() {
        let mut trie = Trie::new();
        trie.insert("s3:GetObject");

        assert!(trie.starts_with("s3:Put").is_empty());
    }

    #[test]
    fn test_empty_prefix_returns_all() {
        let mut trie = Trie::new();
        trie.insert("iam:CreateUser");
        trie.insert("iam:DeleteUser");

        assert_eq!(trie.starts_with("").len(), 2);
    }
}
