#[derive(Debug)]
pub struct ROLEeEvaluator<T: State = Init> {
    state: T,
}

impl ROLEeEvaluator {
    pub fn new() -> Self {
        Self { state: Init {} }
    }
}

impl Default for ROLEeEvaluator {
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
