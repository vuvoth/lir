use std::vec;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, *},
    poly::Rotation,
};

use crate::impl_expr;
use strum_macros::EnumIter;

pub trait LookupTable<F: FieldExt> {
    /// Returns the list of ALL the table columns following the table order.
    fn columns(&self) -> Vec<Column<Any>>;

    /// Returns the list of ALL the table advice columns following the table
    /// order.
    fn advice_columns(&self) -> Vec<Column<Advice>> {
        self.columns()
            .iter()
            .map(|&col| col.try_into())
            .filter_map(|res| res.ok())
            .collect()
    }

    /// Returns the String annotations associated to each column of the table.
    fn annotations(&self) -> Vec<String>;

    /// Return the list of expressions used to define the lookup table.
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.columns()
            .iter()
            .map(|&column| meta.query_any(column, Rotation::cur()))
            .collect()
    }

    /// Annotates a lookup table by passing annotations for each of it's
    /// columns.
    fn annotate_columns(&self, cs: &mut ConstraintSystem<F>) {
        self.columns()
            .iter()
            .zip(self.annotations().iter())
            .for_each(|(&col, ann)| cs.annotate_lookup_any_column(col, || ann))
    }

    /// Annotates columns of a table embedded within a circuit region.
    fn annotate_columns_in_region(&self, region: &mut Region<F>) {
        self.columns()
            .iter()
            .zip(self.annotations().iter())
            .for_each(|(&col, ann)| region.name_column(|| ann, col))
    }
}

impl<F: FieldExt, C: Into<Column<Any>> + Copy, const W: usize> LookupTable<F> for [C; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.iter()
            .map(|column| meta.query_any(*column, Rotation::cur()))
            .collect()
    }

    fn columns(&self) -> Vec<Column<Any>> {
        self.iter().map(|&col| col.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec![]
    }
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum BinOpTag {
    ADD = 1,
    MUL,
    SUB,
    DIV,
    MOD,
    LT,
    GT,
    LE,
    GE,
    SHL,
    SHR,
    AND,
    XOR,
    OR,
    EQ,
}
impl_expr!(BinOpTag);

#[derive(Clone, Debug)]
pub struct BinaryOperationTable {
    pub tag: Column<Fixed>,
    pub lhs: Column<Fixed>,
    pub rhs: Column<Fixed>,
    pub res: Column<Fixed>,
}

impl BinaryOperationTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.fixed_column(),
            lhs: meta.fixed_column(),
            rhs: meta.fixed_column(),
            res: meta.fixed_column(),
        }
    }

    pub fn load<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
        precomputed: Vec<[u8; 4]>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "binop table",
            |mut region| {
                for (offset, v) in precomputed.iter().enumerate() {
                    let tag = v[0] as u64;
                    let lhs = v[1] as u64;
                    let rhs = v[2] as u64;
                    let res = v[3] as u64;
                    region.assign_fixed(
                        || "tag",
                        self.tag,
                        offset,
                        || Value::known(F::from(tag)),
                    )?;
                    region.assign_fixed(
                        || "lhs",
                        self.lhs,
                        offset,
                        || Value::known(F::from(lhs)),
                    )?;
                    region.assign_fixed(
                        || "rhs",
                        self.rhs,
                        offset,
                        || Value::known(F::from(rhs)),
                    )?;
                    region.assign_fixed(
                        || "res",
                        self.res,
                        offset,
                        || Value::known(F::from(res)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

impl<F: FieldExt> LookupTable<F> for BinaryOperationTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.tag.into(),
            self.lhs.into(),
            self.rhs.into(),
            self.res.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tag"),
            String::from("lhs"),
            String::from("rhs"),
            String::from("value"),
        ]
    }
}
#[derive(Clone, Debug, Copy)]
pub enum UnaryOpTag {
    PLUS = 1,
    MINUS,
    NEG,
}
impl_expr!(UnaryOpTag);

#[derive(Clone, Debug)]
pub struct UnaryOperationTable {
    pub tag: Column<Fixed>,
    pub operand: Column<Fixed>,
    pub res: Column<Fixed>,
}

impl UnaryOperationTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.fixed_column(),
            operand: meta.fixed_column(),
            res: meta.fixed_column(),
        }
    }

    pub fn load<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
        precomputed: Vec<[u8; 3]>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "unaryop table",
            |mut table| {
                for (offset, v) in precomputed.iter().enumerate() {
                    let tag = v[0] as u64;
                    let operand = v[1] as u64;
                    let res = v[2] as u64;
                    table.assign_fixed(
                        || "tag",
                        self.tag,
                        offset,
                        || Value::known(F::from(tag)),
                    )?;
                    table.assign_fixed(
                        || "operand",
                        self.operand,
                        offset,
                        || Value::known(F::from(operand)),
                    )?;
                    table.assign_fixed(
                        || "res",
                        self.res,
                        offset,
                        || Value::known(F::from(res)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BlockExitTag {
    JUMP = 1,
    CONDJUMP,
    RET,
}
impl_expr!(BlockExitTag);

#[derive(Clone, Debug)]
pub struct BlockExitTable {
    pub tag: Column<Fixed>,
    pub cond: Column<Fixed>,
    pub from: Column<Fixed>,
    pub to: Column<Fixed>,
}

impl BlockExitTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.fixed_column(),
            cond: meta.fixed_column(),
            from: meta.fixed_column(),
            to: meta.fixed_column(),
        }
    }

    pub fn load<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "blockexit table",
            |mut table| {
                // TODO
                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct CallTable {
    pub from: Column<Fixed>,
    pub to: Column<Fixed>,
}

impl CallTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            from: meta.fixed_column(),
            to: meta.fixed_column(),
        }
    }

    pub fn load<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "blockexit table",
            |mut table| {
                // TODO
                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct RegisterTable {
    pub index: Column<Fixed>,
    pub value: Column<Advice>,
}

impl<F: FieldExt> LookupTable<F> for RegisterTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![self.index.into(), self.value.into()]
    } 
    fn annotations(&self) -> Vec<String> {
        vec![String::from("index"), String::from("value")]   
    }
}

impl RegisterTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            index: meta.fixed_column(),
            value: meta.advice_column_in(SecondPhase),
        }
    }

    fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: (Value<F>, Value<F>),
    ) -> Result<(), Error> {
        region.assign_fixed(|| "assign index", self.index, offset, || row.0)?;
        region.assign_advice(|| "assign register value", self.value, offset, || row.1)?;
        Ok(())
    }
}
