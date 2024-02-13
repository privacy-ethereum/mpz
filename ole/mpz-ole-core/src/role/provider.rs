#[derive(Debug)]
pub struct ROLEeProvider<T: State = Init> {
    state: T,
}

impl ROLEeProvider {
    pub fn new() -> Self {
        Self { state: Init {} }
    }
}

impl Default for ROLEeProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct Init {}

pub trait State: sealed::Sealed {}
impl State for Init {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Init {}
}
