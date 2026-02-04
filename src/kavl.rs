// src/kavl.rs
//
// Rust replacement for kavl.h (Attractive Chaos AVL macros).
//
// We do NOT attempt a macro-for-macro port. Instead we provide a small, predictable API
// that covers what ByeDPI actually uses from KAVL in this repo: ordered set/map-style
// operations with an optional “rank” counter (cnt_) and iteration.
//
// Implementation note:
// - For the current “postrочный” port stage, this uses a Vec-backed ordered container
//   (binary search + insert/remove). This matches what we already did in mpool.rs and
//   keeps Windows-first builds simple.
// - If later you need AVL performance characteristics, we can swap the backend to a real AVL/RB tree
//   without changing call sites much.

#![allow(dead_code)]

use core::cmp::Ordering;

pub const KAVL_MAX_DEPTH: usize = 64;

pub struct KavlSet<T, C>
where
    C: Fn(&T, &T) -> Ordering,
{
    items: Vec<T>,
    cmp: C,
}

impl<T, C> KavlSet<T, C>
where
    C: Fn(&T, &T) -> Ordering,
{
    pub fn new(cmp: C) -> Self {
        Self {
            items: Vec::new(),
            cmp,
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.items.iter()
    }

    // Equivalent to kavl_find_* with cnt_ (rank, 1-based in C; we expose 0-based index).
    pub fn find_with_rank(&self, key: &T) -> (Option<&T>, usize) {
        match self.items.binary_search_by(|p| (self.cmp)(key, p)) {
            Ok(idx) => (Some(&self.items[idx]), idx),
            Err(idx) => (None, idx),
        }
    }

    // Equivalent to kavl_insert_* with cnt_.
    // Returns (&existing_or_inserted, inserted?, rank_index)
    pub fn insert_with_rank(&mut self, val: T) -> (&T, bool, usize) {
        match self.items.binary_search_by(|p| (self.cmp)(&val, p)) {
            Ok(idx) => (&self.items[idx], false, idx),
            Err(idx) => {
                self.items.insert(idx, val);
                (&self.items[idx], true, idx)
            }
        }
    }

    // Equivalent to kavl_erase_* with cnt_.
    // If key exists, removes it and returns it.
    pub fn erase_with_rank(&mut self, key: &T) -> (Option<T>, usize) {
        match self.items.binary_search_by(|p| (self.cmp)(key, p)) {
            Ok(idx) => (Some(self.items.remove(idx)), idx),
            Err(idx) => (None, idx),
        }
    }

    // Convenience: find without rank.
    pub fn find(&self, key: &T) -> Option<&T> {
        self.find_with_rank(key).0
    }

    // Convenience: insert without rank.
    pub fn insert(&mut self, val: T) -> bool {
        self.insert_with_rank(val).1
    }

    // Convenience: erase without rank.
    pub fn erase(&mut self, key: &T) -> Option<T> {
        self.erase_with_rank(key).0
    }
}
