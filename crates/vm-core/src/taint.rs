use crate::bitset::BitSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Public,
    Private,
    Blind,
}

impl Class {
    pub(crate) fn symbolic(held: bool) -> Self {
        if held { Class::Private } else { Class::Blind }
    }
}

impl From<crate::Visibility> for Class {
    fn from(v: crate::Visibility) -> Self {
        match v {
            crate::Visibility::Public => Class::Public,
            crate::Visibility::Private => Class::Private,
            crate::Visibility::Blind => Class::Blind,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Taints {
    symbolic: BitSet,
    unheld: BitSet,
}

impl Taints {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn class(&self, i: u32) -> Class {
        if !self.symbolic.contains(i) {
            Class::Public
        } else if self.unheld.contains(i) {
            Class::Blind
        } else {
            Class::Private
        }
    }

    pub(crate) fn is_symbolic(&self, i: u32) -> bool {
        self.symbolic.contains(i)
    }

    pub(crate) fn is_held(&self, i: u32) -> bool {
        !self.unheld.contains(i)
    }

    pub(crate) fn any_symbolic(&self, addr: u32, len: usize) -> bool {
        self.symbolic.contains_any(addr, len)
    }

    pub(crate) fn any_unheld(&self, addr: u32, len: usize) -> bool {
        self.unheld.contains_any(addr, len)
    }

    pub(crate) fn symbolic_mask(&self, addr: u32, len: u32) -> u8 {
        self.symbolic.compute_mask(addr, len)
    }

    pub(crate) fn set(&mut self, i: u32, class: Class) {
        match class {
            Class::Public => {
                self.symbolic.remove(i);
                self.unheld.remove(i);
            }
            Class::Private => {
                self.symbolic.insert(i);
                self.unheld.remove(i);
            }
            Class::Blind => {
                self.symbolic.insert(i);
                self.unheld.insert(i);
            }
        }
    }

    pub(crate) fn set_range(&mut self, addr: u32, len: usize, class: Class) {
        match class {
            Class::Public => {
                self.symbolic.remove_range(addr, len);
                self.unheld.remove_range(addr, len);
            }
            Class::Private => {
                self.symbolic.insert_range(addr, len);
                self.unheld.remove_range(addr, len);
            }
            Class::Blind => {
                self.symbolic.insert_range(addr, len);
                self.unheld.insert_range(addr, len);
            }
        }
    }

    pub(crate) fn mark_symbolic_range(&mut self, addr: u32, len: usize) {
        self.symbolic.insert_range(addr, len);
    }

    pub(crate) fn mark_held(&mut self, i: u32) {
        self.unheld.remove(i);
    }

    pub(crate) fn copy(&mut self, src: u32, dst: u32, len: usize) {
        self.symbolic.copy(src, dst, len);
        self.unheld.copy(src, dst, len);
    }
}
