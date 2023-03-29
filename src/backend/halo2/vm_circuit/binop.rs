use std::marker::PhantomData;

use crate::backend::halo2::table::BinOpTag;
use strum::IntoEnumIterator;

use super::BinaryOperationTable;
use super::RegisterTable;
use super::SubCircuit;
use halo2_proofs::{
    circuit::Layouter,
    halo2curves::FieldExt,
    plonk::{Advice, Column, Error},
};

fn generate_binop_table(range: u8) -> Vec<[u8; 4]> {
    let mut all_cases = vec![];
    // TODO: for all cases
    let r = 1 << range;
    for x in 0..r {
        for y in 0..r {
            let mut simple_record: [u8; 4] = [0, 0, 0, 0];
            for op in BinOpTag::iter() {
                simple_record[1] = x;
                simple_record[2] = y;
                simple_record[0] = op as u8;
                simple_record[3] = match op {
                    BinOpTag::ADD => x + y,
                    BinOpTag::MUL => x * y,
                    BinOpTag::SUB => x + y,
                    BinOpTag::DIV => {
                        if y != 0 {
                            x / y
                        } else {
                            0
                        }
                    }
                    BinOpTag::LT => (x < y) as u8,
                    BinOpTag::GT => (x > y) as u8,
                    BinOpTag::LE => (x <= y) as u8,
                    BinOpTag::GE => (x >= y) as u8,
                    BinOpTag::SHL => (x << y) as u8,
                    BinOpTag::SHR => (x >> y) as u8,
                    BinOpTag::AND => x & y,
                    BinOpTag::XOR => x ^ y,
                    BinOpTag::OR => x | y,
                    BinOpTag::EQ => (x == y) as u8,
                    BinOpTag::MOD => {
                        if y != 0 {
                            x % y
                        } else {
                            0
                        }
                    }
                };
                all_cases.push(simple_record);
            }
        }
    }

    all_cases
}

pub struct BinOpConfig<F: FieldExt> {
    binop_table: BinaryOperationTable,
    register_table: RegisterTable,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BinOpConfig<F> {
    pub fn load_binop_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let precomputed_binop = generate_binop_table(4);
        self.binop_table.load(layouter, precomputed_binop)?;
        Ok(())
    }
}

pub struct BinOpCircuit<F: FieldExt> {
    _marker: PhantomData<F>,
}

// impl<F: FieldExt> SubCircuit<F> for BinOpCircuit<F> {
//     type Config = BinOpConfig<F>;

//     fn synthesize_sub(
//         &self,
//         config: &Self::Config,
//         layouter: &mut impl Layouter<F>,
//     ) -> Result<(), Error> {
//         config.load_binop_table(layouter)?;
//         Ok(())
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_binop_table_test() {
        let binop_table = generate_binop_table(1);
        println!("{:?}", binop_table);
    }
}
