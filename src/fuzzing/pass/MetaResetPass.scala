// Copyright 2017-2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Jack Koenig <koenig@sifive.com>, Kevin Laeufer <laeufer@cs.berkeley.edu>

package fuzzing.pass

import firrtl.Utils.throwInternalError
import firrtl._
import firrtl.analyses.InstanceKeyGraph
import firrtl.stage.Forms

// Add a meta-reset to all registers
// see: https://people.eecs.berkeley.edu/~laeufer/papers/rfuzz_kevin_laeufer_iccad2018.pdf
object MetaResetPass extends Transform with DependencyAPIMigration {
  override def prerequisites = Forms.LowForm

  override def invalidates(a: Transform) = false

  private val metaResetPort = ir.Port(ir.NoInfo, "metaReset", ir.Input, Utils.BoolType)
  private val metaResetInput = ir.Reference(metaResetPort.name, metaResetPort.tpe, PortKind, SourceFlow)
  private def metaResetInstPort(inst: WDefInstance) = {
    val instRef = ir.Reference(inst.name, inst.tpe, InstanceKind, DuplexFlow)
    ir.SubField(instRef, metaResetPort.name, metaResetPort.tpe, SourceFlow)
  }

  // Make a firrtl util
  private def getZero(tpe: ir.Type): ir.Literal = tpe match {
    case gtpe: ir.GroundType =>
      passes.RemoveValidIf.getGroundZero(gtpe).mapWidth { w: ir.Width => gtpe.width }.asInstanceOf[ir.Literal]
    case other => throwInternalError(s"Unexpected non-GroundType $other")
  }

  private def onStmt(modType: Map[String, ir.Type])(stmt: ir.Statement): ir.Statement =
    stmt.mapStmt(onStmt(modType)) match {
      case reg: ir.DefRegister =>
        if (reg.reset != Utils.zero) {
          throwInternalError(s"Resets must have been removed! Got ${reg.serialize}")
        }
        val zero = getZero(reg.tpe)
        reg.copy(reset = metaResetInput, tpe = zero.tpe, init = zero)
      case inst: ir.DefInstance if (modType.contains(inst.module)) =>
        val instx = inst.copy(tpe = modType(inst.module))
        val con = ir.Connect(ir.NoInfo, metaResetInstPort(instx), metaResetInput)
        ir.Block(Seq(instx, con))
      case other => other
    }
  private def onMod(modType: Map[String, ir.Type])(m: ir.Module): ir.Module = {
    val portsx = metaResetPort +: m.ports
    val bodyx = onStmt(modType)(m.body)
    m.copy(ports = portsx, body = bodyx)
  }
  def cleanup: Seq[Transform] = Seq(firrtl.transforms.RemoveReset)

  override def execute(state: CircuitState): CircuitState = {
    val modsLeafToRoot = InstanceKeyGraph(state.circuit).moduleOrder.reverse
    val (modsUpdate, _) =
      modsLeafToRoot.foldLeft((Map.empty[String, ir.DefModule], Map.empty[String, ir.Type])) {
        case ((acc, types), m) => m match {
          case mod: ir.Module =>
            val modx = onMod(types)(mod)
            (acc + (modx.name -> modx), types + (modx.name -> Utils.module_type(modx)))
          case _ => (acc, types)
        }
      }
    // Maintain order
    val modsx = state.circuit.modules.map(m => modsUpdate.getOrElse(m.name, m))
    val res = state.copy(circuit = state.circuit.copy(modules = modsx))
    cleanup.foldLeft(res) { case (in, xform) => xform.runTransform(in) }
  }
}
