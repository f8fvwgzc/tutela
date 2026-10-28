//! The product's side: the resource tree with an ancestors list per node.
//! Tutela never stores this; the SDK loads paths by id. THROWAWAY.

use crate::model::{Attrs, NodeId, TypeId};

pub const NO_PARENT: NodeId = u32::MAX;

pub struct Tree {
    pub parent: Vec<NodeId>,
    pub ty: Vec<TypeId>,
    pub attrs: Vec<Attrs>,
    off: Vec<u32>,
    anc: Vec<NodeId>,
}

/// Where the evaluator gets the path of a scope it must place (spike
/// question §8 in docs/SPIKE-WEEK1.md).
pub trait ScopePaths {
    /// Ancestors, nearest first; the last one is the org.
    fn ancestors(&self, n: NodeId) -> &[NodeId];
    fn ty(&self, n: NodeId) -> TypeId;
}

impl Tree {
    pub fn new() -> Tree {
        Tree { parent: Vec::new(), ty: Vec::new(), attrs: Vec::new(), off: vec![0], anc: Vec::new() }
    }

    /// Adds a node. The parent must exist already, so ids are topological.
    pub fn add(&mut self, parent: NodeId, ty: TypeId, attrs: Attrs) -> NodeId {
        let id = self.parent.len() as NodeId;
        self.parent.push(parent);
        self.ty.push(ty);
        self.attrs.push(attrs);
        if parent != NO_PARENT {
            self.anc.push(parent);
            let (s, e) = (self.off[parent as usize] as usize, self.off[parent as usize + 1] as usize);
            for i in s..e {
                let a = self.anc[i];
                self.anc.push(a);
            }
        }
        self.off.push(self.anc.len() as u32);
        id
    }

    pub fn len(&self) -> usize {
        self.parent.len()
    }

    pub fn depth(&self, n: NodeId) -> usize {
        self.ancestors(n).len()
    }
}

impl ScopePaths for Tree {
    fn ancestors(&self, n: NodeId) -> &[NodeId] {
        &self.anc[self.off[n as usize] as usize..self.off[n as usize + 1] as usize]
    }
    fn ty(&self, n: NodeId) -> TypeId {
        self.ty[n as usize]
    }
}
