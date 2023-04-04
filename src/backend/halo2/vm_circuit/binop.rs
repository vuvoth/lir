use std::marker::PhantomData;
use std::vec;

use crate::backend::halo2::table::{BinOpTag, LookupTable};
use crate::backend::halo2::utils::SubCircuitConfig;
use halo2_proofs::circuit::{Region, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::Circuit;
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
                    // BinOpTag::SHL => (x << y) as u8,
                    // BinOpTag::SHR => (x >> y) as u8,
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
                    _ => {
                        0
                    }
                };
                all_cases.push(simple_record);
            }
        }
    }

    all_cases
}

#[derive(Clone, Debug)]
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

    pub fn load_binop_row(
        &self,
        region: &mut Region<'_, F>,
        tag: F,
        lhs: F,
        rhs: F,
        res: F,
    ) -> Result<(), Error> {
        let offset = 0;
        region.assign_advice(|| "tag", self.tag_column, offset, || Value::known(tag))?;
        region.assign_advice(|| "lhs", self.lhs_column, offset, || Value::known(lhs))?;
        region.assign_advice(|| "rhs", self.rhs_column, offset, || Value::known(rhs))?;
        region.assign_advice(|| "res", self.res_column, offset, || Value::known(res))?;
        Ok(())
    }
}

pub struct BinOpConfigArgs {
    binop_table: BinaryOperationTable,
    register_table: RegisterTable,
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

        meta.lookup_any("bin_op_lookup", |meta| {
            let tag_precompute = meta.query_fixed(binop_table.tag, Rotation::cur());
            let tag_value = meta.query_advice(tag_column, Rotation::cur());
            let lhs_precompute = meta.query_fixed(binop_table.lhs, Rotation::cur());
            let lhs_value = meta.query_advice(lhs_column, Rotation::cur());
            let rhs_precompute = meta.query_fixed(binop_table.rhs, Rotation::cur());
            let rhs_value = meta.query_advice(rhs_column, Rotation::cur());
            let res_precompute = meta.query_fixed(binop_table.res, Rotation::cur());
            let res_value = meta.query_advice(res_column, Rotation::cur());
            vec![
                (tag_value, tag_precompute),
                (lhs_value, lhs_precompute),
                (rhs_value, rhs_precompute),
                (res_value, res_precompute),
            ]
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

#[derive(Clone, Debug, Default)]
pub struct BinOpCircuit<F: FieldExt> {
    tag: F,
    lhs: F,
    rhs: F,
    res: F,
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
        layouter.assign_region(
            || "bin_op",
            |mut region| {
                config.load_binop_row(&mut region, self.tag, self.lhs, self.rhs, self.res)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

impl<F: FieldExt> Circuit<F> for BinOpCircuit<F> {
    type Config = BinOpConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        BinOpCircuit::default()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let binop_table = BinaryOperationTable::construct(meta);
        let register_table = RegisterTable::construct(meta);
        BinOpConfig::new(
            meta,
            BinOpConfigArgs {
                binop_table,
                register_table,
            },
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.synthesize_sub(&config, &mut layouter)?;
        Ok(())
    }
}

impl<F: FieldExt> BinOpCircuit<F> {
    pub fn new(op: u64, lhs: u64, rhs: u64, res: u64) -> Self {
        Self {
            tag: F::from_u128(op as u128),
            lhs: F::from_u128(lhs as u128),
            rhs: F::from_u128(rhs as u128),
            res: F::from_u128(res as u128),
            _marker: PhantomData,
        }
    }
}
#[cfg(test)]
mod tests {
    

    use halo2_proofs::{halo2curves::bn256::Fr, dev::MockProver};

    use super::*;

    #[test]
    fn generate_binop_table_test() {
        generate_binop_table(4);
    }

    #[test]
    fn circuit_test() {
        let k = 20;
        let circuit = BinOpCircuit::<Fr>::new(1, 1, 1, 1);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.verify().unwrap();
    }
}
