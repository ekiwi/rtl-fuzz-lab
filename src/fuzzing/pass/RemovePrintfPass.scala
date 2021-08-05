// Copyright 2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Kevin Laeufer <laeufer@cs.berkeley.edu>

package fuzzing.pass

import firrtl._
import firrtl.options.Dependency

/** Removes all printf statements. */
object RemovePrintfPass extends Transform with DependencyAPIMigration {
  override def prerequisites = Seq(
    Dependency[firrtl.transforms.RemoveWires],
    Dependency(passes.ExpandWhens),
    Dependency(passes.LowerTypes)
  )
  override def invalidates(a: Transform) = false

  override def execute(state: CircuitState): CircuitState = {
    val circuit = state.circuit.mapModule(onModule)
    state.copy(circuit = circuit)
  }

  private def onModule(m: ir.DefModule): ir.DefModule = m match {
    case mod: ir.Module => mod.mapStmt(onStmt)
    case other => other
  }

  private def onStmt(s: ir.Statement): ir.Statement = s match {
    case _: ir.Print => ir.EmptyStmt
    case other => other.mapStmt(onStmt)
  }
}
