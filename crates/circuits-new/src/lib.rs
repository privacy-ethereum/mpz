use mpz_fields::Field;

pub mod sha256;

/// A wire that may be constant.
#[derive(Debug, Clone, Copy)]
pub enum MaybeConst<A, B> {
    /// A variable wire.
    Var(A),
    /// A constant wire.
    Const(B),
}

/// Circuit-evaluation context.
pub trait Context {
    type Error;
    type Wire: Copy;
    type Field: Field;

    fn add(&mut self, a: Self::Wire, b: Self::Wire) -> Self::Wire;

    fn sub(&mut self, a: Self::Wire, b: Self::Wire) -> Self::Wire;

    fn mul(&mut self, a: Self::Wire, b: Self::Wire) -> Self::Wire;

    fn mul_const(&mut self, a: Self::Wire, b: Self::Field) -> MaybeConst<Self::Wire, Self::Field> {
        if b == Field::zero() {
            MaybeConst::Const(Field::zero())
        } else if b == Field::one() {
            MaybeConst::Var(a)
        } else {
            let b = self.constant(b);
            MaybeConst::Var(self.mul(a, b))
        }
    }

    /// Public constant wire.
    fn constant(&mut self, v: Self::Field) -> Self::Wire;

    /// Assert that `v` equals the constant value `expected`.
    fn assert_const(&mut self, v: Self::Wire, expected: Self::Field) -> Result<(), Self::Error>;

    /// Assert that two wires carry equal values.
    fn assert_eq(&mut self, a: Self::Wire, b: Self::Wire) -> Result<(), Self::Error> {
        let diff = self.sub(a, b);
        self.assert_const(diff, Self::Field::zero())
    }
}

/// Witness-generation context.
pub struct WitnessCtx<'a, T> {
    pub witness: &'a mut Vec<T>,
}

#[derive(Debug)]
pub struct WitnessError;

impl<T: Field> Context for WitnessCtx<'_, T> {
    type Error = WitnessError;
    type Wire = T;
    type Field = T;

    fn add(&mut self, a: T, b: T) -> T {
        a + b
    }

    fn sub(&mut self, a: T, b: T) -> T {
        a - b
    }

    fn mul(&mut self, a: T, b: T) -> T {
        let z = a * b;
        self.witness.push(z);
        z
    }

    fn constant(&mut self, v: T) -> T {
        v
    }

    fn assert_const(&mut self, v: T, expected: T) -> Result<(), WitnessError> {
        if v != expected {
            return Err(WitnessError);
        }
        Ok(())
    }
}
