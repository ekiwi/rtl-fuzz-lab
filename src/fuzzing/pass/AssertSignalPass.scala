// Copyright 2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Kevin Laeufer <laeufer@cs.berkeley.edu>

package fuzzing.pass

import firrtl._
import firrtl.options.Dependency
import scala.collection.mutable

/** Turns all asserts and stop with a non-zero exit code into a single global `assert_failed` output. */
object AssertSignalPass extends Transform with DependencyAPIMigration {
  override def prerequisites = Seq(
    Dependency[firrtl.transforms.RemoveWires],
    Dependency(passes.ExpandWhens),
    Dependency(passes.LowerTypes),
    Dependency(firrtl.transforms.EnsureNamedStatements)
  )
  override def invalidates(a: Transform) = false

  override def execute(state: CircuitState): CircuitState = {
    val portNames = findPortNames(state)
    val circuit = state.circuit.mapModule(onModule(_, portNames))
    state.copy(circuit = circuit)
  }

  val DefaultPortName = "assert_failed"

  // determines the name of the output port for every module in the hierarchy
  private def findPortNames(state: CircuitState): Map[String, String] = state.circuit.modules.flatMap {
    case mod: ir.Module =>
      val namespace = Namespace(mod)
      Some(mod.name -> namespace.newName(DefaultPortName))
    case _ => None
  }.toMap

  private def onModule(m: ir.DefModule, portNames: Map[String, String]): ir.DefModule = m match {
    case mod: ir.Module =>
      val asserts = mutable.ListBuffer[ir.DefNode]()
      val modWithoutAssert = onStmt(mod.body, asserts, portNames)

      // generate a signal that indicates whether any assertion failed
      val anyFailed: ir.Expression = if(asserts.isEmpty) { Utils.False() } else {
        asserts.map(a => if(a.name.nonEmpty) ir.Reference(a) else a.value).reduce(Utils.or)
      }

      // generate the output port and the connection to it
      val portName = portNames(mod.name)
      val outPort = ir.Port(ir.NoInfo, portName, ir.Output, Utils.BoolType)
      val connectOut = ir.Connect(ir.NoInfo, ir.Reference(outPort), anyFailed)

      // put everything together
      val stmts = modWithoutAssert +: asserts.filterNot(_.name.isEmpty) :+ connectOut
      mod.copy(ports = m.ports :+ outPort, body = ir.Block(stmts))
    case other => other
  }

  private def onStmt(s: ir.Statement, asserts: mutable.ListBuffer[ir.DefNode], portNames: Map[String, String]): ir.Statement = s match {
    case s : ir.Stop if s.ret != 0 =>
      asserts.append(ir.DefNode(s.info, s.name, s.en))
      ir.EmptyStmt
    case v: ir.Verification if v.op == ir.Formal.Assert =>
      asserts.append(ir.DefNode(v.info, v.name, Utils.and(v.en, Utils.not(v.pred))))
      ir.EmptyStmt
    case i: ir.DefInstance =>
      portNames.get(i.module) match {
        case Some(portName) =>
          // add port to instance type
          val fields = i.tpe.asInstanceOf[ir.BundleType].fields
          val tpe = ir.BundleType(fields :+ ir.Field(portName, Utils.to_flip(ir.Output), Utils.BoolType))
          val newI = i.copy(tpe = tpe)
          // if an assert in the submodule fails, the global assert fails
          val assertOut = ir.SubField(ir.Reference(newI), portName, Utils.BoolType)
          asserts.append(ir.DefNode(ir.NoInfo, "", assertOut))
          newI
        case None => i // e.g., ExtModules won't have an assert out port
      }
    case other => other.mapStmt(onStmt(_, asserts, portNames))
  }
}
