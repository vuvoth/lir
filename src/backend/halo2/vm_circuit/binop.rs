use std::marker::PhantomData;
use std::vec;

use crate::backend::halo2::table::{BinOpTag, LookupTable};
use crate::backend::halo2::utils::SubCircuitConfig;
use halo2_proofs::poly::Rotation;
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
    let r = 1 << range;
    for x in 0..r {
        for y in 0..r {
            let mut simple_record: [u8; 4] = [0, 0, 0, 0];
            for op in BinOpTag::iter() {
                simple_record[0] = op as u8;
                simple_record[1] = x;
                simple_record[2] = y;
                simple_record[3] = match op {
                    BinOpTag::ADD => x + y,
                    BinOpTag::MUL => x * y,
                    BinOpTag::SUB => {
                        if x >= y {
                            x - y
                        } else {
                            0
                        }
                    }
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
    tag_column: Column<Advice>,
    lhs_column: Column<Advice>,
    rhs_column: Column<Advice>,
    res_column: Column<Advice>, 
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

pub struct BinOpConfigArgs {
    binop_table: BinaryOperationTable,
    register_table: RegisterTable
}


impl<F: FieldExt> SubCircuitConfig<F> for BinOpConfig<F> {
    type ConfigArgs = BinOpConfigArgs;
    fn new(
        meta: &mut halo2_proofs::plonk::ConstraintSystem<F>,
        Self::ConfigArgs {
            binop_table,
            register_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let tag_column = meta.advice_column();
        let lhs_column = meta.advice_column();
        let rhs_column = meta.advice_column();
        let res_column = meta.advice_column();

        binop_table.annotate_columns(meta);
        register_table.annotate_columns(meta);

        meta.lookup_any("bin_op_lookup",|meta| {
            let tag_precompute = meta.query_fixed(binop_table.tag, Rotation::cur());
            let tag_value = meta.query_advice(tag_column, Rotation::cur());
            let lhs_precompute = meta.query_fixed(binop_table.lhs, Rotation::cur());
            let lhs_value = meta.query_advice(lhs_column, Rotation::cur());
            let rhs_precompute = meta.query_fixed(binop_table.rhs, Rotation::cur());
            let rhs_value = meta.query_advice(rhs_column, Rotation::cur());
            let res_precompute = meta.query_fixed(binop_table.res, Rotation::cur());
            let res_value = meta.query_advice(res_column, Rotation::cur());
            vec![(tag_value, tag_precompute), (lhs_value, lhs_precompute), (rhs_value, rhs_precompute), (res_value, res_precompute)]
        });

        Self {
            tag_column, 
            lhs_column,
            rhs_column,
            res_column,
            binop_table,
            register_table,
            _marker: PhantomData,  
        }
        
    }
}

pub struct BinOpCircuit<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> SubCircuit<F> for BinOpCircuit<F> {
    type Config = BinOpConfig<F>;

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_binop_table(layouter)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_binop_table_test() {
        let binop_table = generate_binop_table(1);
    }
}
