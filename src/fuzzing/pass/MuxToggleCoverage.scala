// Copyright 2017-2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Jack Koenig <koenig@sifive.com>, Kevin Laeufer <laeufer@cs.berkeley.edu>

package fuzzing.pass

import fuzzing.annotations.{DoNotCoverAnnotation, MuxToggleOpAnnotation}
import firrtl._
import firrtl.annotations._
import firrtl.options.Dependency

import scala.collection.mutable

// adds mux toggle coverage with a coverage statement
// see: https://people.eecs.berkeley.edu/~laeufer/papers/rfuzz_kevin_laeufer_iccad2018.pdf
// TODO: this transform should build upon the standard toggle coverage pass once that is published + polished!
object MuxToggleCoverage extends Transform with DependencyAPIMigration {
  override def prerequisites = Seq(
    Dependency[firrtl.transforms.RemoveWires],
    Dependency(passes.ExpandWhens),
    Dependency(passes.LowerTypes)
  )
  override def invalidates(a: Transform) = false

  override def execute(state: CircuitState): CircuitState = {
    val c = CircuitTarget(state.circuit.main)

    val newAnnos = mutable.ListBuffer[Annotation]()
    val fullToggleAnnotation = state.annotations.collectFirst { case o: MuxToggleOpAnnotation => o }.get
    val useFullToggle: Boolean = fullToggleAnnotation.fullToggle
    newAnnos += fullToggleAnnotation

    val circuit = state.circuit.mapModule(onModule(_, collectModulesToIgnore(state), c, newAnnos, useFullToggle))
    //println(circuit.serialize)
    state.copy(circuit = circuit, annotations = newAnnos.toList ++: state.annotations)
  }

  private def onModule(m: ir.DefModule, ignoreSet: Set[String], c: CircuitTarget, newAnnos: mutable.ListBuffer[Annotation], useFullToggle: Boolean): ir.DefModule = m match {
    case mod: ir.Module if !ignoreSet.contains(mod.name) =>
      val ctx = ModuleCtx(c.module(mod.name), Namespace(mod), newAnnos, findClock(mod), findReset(mod), useFullToggle)
      val conds = findMuxConditions(mod)
      val (stmts, annos) = coverToggle(ctx, conds)
      assert(annos.isEmpty)
      mod.copy(body = ir.Block(mod.body +: stmts))
    case other => other
  }

  def collectModulesToIgnore(state: CircuitState): Set[String] = {
    val main = state.circuit.main
    state.annotations.collect { case DoNotCoverAnnotation(target) if target.circuit == main => target.module }.toSet
  }

  // TODO: replace with library function
  private def findClock(m: ir.Module): ir.Expression = {
    m.ports.collectFirst { case p @ ir.Port(_, _, ir.Input, ir.ClockType) => ir.Reference(p) }.getOrElse(
      throw new RuntimeException(s"Couldn't find a clock input for:\n${m.serialize}")
    )
  }

  // TODO: replace with library function
  private def findReset(m: ir.Module): ir.Expression = {
    m.ports.find(_.name == "reset").map(p => ir.Reference(p)).getOrElse(
      throw new RuntimeException(s"Couldn't find a reset input for:\n${m.serialize}")
    )
  }

  private case class ModuleCtx(m: ModuleTarget, namespace: Namespace, newAnnos: mutable.ListBuffer[Annotation],
    clock: ir.Expression, reset: ir.Expression, useFullToggle: Boolean)

  private def coverToggle(ctx: ModuleCtx, conds: List[ir.Expression]): (List[ir.Statement], List[Annotation]) = {
    // Tracks the previous value of the reset signal
    val prevReset = ir.DefRegister(ir.NoInfo, ctx.namespace.newName("prev_reset"), Utils.BoolType, ctx.clock, Utils.zero, Utils.zero)
    val prevResetRef = ir.Reference(prevReset)
    val prevResetConnect = ir.Connect(ir.NoInfo, prevResetRef, ctx.reset)

    // Iterates through each passed in condition (most are ir.Reference)
    val stmts: List[ir.Statement] = conds.flatMap { muxCond =>
      // Get name of reference to use to identify the current condition
      val name: String = muxCond match {
        case ir.Reference(name, _, _, _) => name
        case _ => "mux_cond"
      }

      // Tracks the current boolean value of the given condition
      val cond = ir.DefNode(ir.NoInfo, ctx.namespace.newName(name + "_s"), muxCond)
      val condRef = ir.Reference(cond)

      // Tracks the previous value of the condition
      val prevCond = ir.DefRegister(ir.NoInfo, ctx.namespace.newName(name + "_prev"), Utils.BoolType, ctx.clock, Utils.zero, Utils.zero)
      val prevCondRef = ir.Reference(prevCond)
      val prevCondConnect = ir.Connect(ir.NoInfo, prevCondRef, condRef)

      // Tracks whether the condition has toggled on a given cycle
      val toggle = ir.DefNode(ir.NoInfo, ctx.namespace.newName(name + "_toggle"), ir.DoPrim(PrimOps.Xor, Seq(condRef, prevCondRef), Seq.empty, Utils.BoolType))
      // Tracks toggles but ignores them when reset is on
      val toggleNoReset = ir.DefNode(ir.NoInfo, ctx.namespace.newName(name + "_toggleNoReset"), Utils.and(ir.Reference(toggle), Utils.not(Utils.or(ctx.reset, prevResetRef))))

      if (!ctx.useFullToggle) {

        val toggleNoResetCov = ir.Verification(ir.Formal.Cover, ir.NoInfo, ctx.clock, ir.Reference(toggleNoReset), Utils.one, ir.StringLit(""), ctx.namespace.newName(name + "_toggleNoResetCov"))
        List(cond, prevCond, prevCondConnect, toggle, toggleNoReset, toggleNoResetCov)

      } else {
        val toggleNoResetRef = ir.Reference(toggleNoReset)

        // Invert value of toggleStore when a toggle is seen. Initialized at 0.
        val toggleStore = ir.DefRegister(ir.NoInfo, ctx.namespace.newName(name + "_toggleStore"), Utils.BoolType, ctx.clock, Utils.zero, Utils.zero)
        val toggleStoreRef = ir.Reference(toggleStore)
        val toggleStoreSwitch = ir.DoPrim(PrimOps.Xor, Seq(toggleStoreRef, toggleNoResetRef), Seq.empty, Utils.BoolType)
        val toggleStoreConnect = ir.Connect(ir.NoInfo, toggleStoreRef, toggleStoreSwitch)

        // 1 when a full toggle has occurred. Counted as when toggleStore is 1 and toggle is 1
        val fullToggle = ir.DefNode(ir.NoInfo, ctx.namespace.newName(name + "_fullToggleNoReset"), Utils.and(toggleStoreRef, toggleNoResetRef))
        val fullToggleCov = ir.Verification(ir.Formal.Cover, ir.NoInfo, ctx.clock, ir.Reference(fullToggle), Utils.one, ir.StringLit(""), ctx.namespace.newName(name + "_fullToggleNoResetCov"))

        List(cond, prevCond, prevCondConnect, toggle, toggleNoReset, toggleStore, toggleStoreConnect, fullToggle, fullToggleCov)
      }
    }
    (prevReset :: prevResetConnect :: stmts, List())
  }

  // returns a list of unique (at least structurally unique!) mux conditions used in the module
  private def findMuxConditions(m: ir.Module): List[ir.Expression] = {
    val conds = mutable.LinkedHashMap[String, ir.Expression]()

    def onStmt(s: ir.Statement): Unit = s match {
      case ir.Block(stmts) => stmts.foreach(onStmt)
      case other => other.foreachExpr(onExpr)
    }
    def onExpr(e: ir.Expression): Unit = {
      e.foreachExpr(onExpr)
      e match {
        case ir.Mux(cond, _, _, _) =>
          val key = cond.serialize
          conds(key) = cond
        case _ =>
      }
    }
    onStmt(m.body)
    conds.values.toList
  }

  private def coverPseudoToggle(ctx: ModuleCtx, conds: List[ir.Expression]): (List[ir.Statement], List[Annotation]) = {
    val stmts = conds.flatMap { cond =>
      val name = cond match {
        case ir.Reference(name, _, _, _) => name
        case _ => "mux_cond"
      }
      val node = ir.DefNode(ir.NoInfo, ctx.namespace.newName(name + "_s"), cond)
      val nodeRef = ir.Reference(node)
      val oneCover = ir.Verification(ir.Formal.Cover, ir.NoInfo, ctx.clock, nodeRef, Utils.not(ctx.reset),
        ir.StringLit(""), ctx.namespace.newName(name + "_one"))
      val zeroCover = ir.Verification(ir.Formal.Cover, ir.NoInfo, ctx.clock, Utils.not(nodeRef), Utils.not(ctx.reset),
        ir.StringLit(""), ctx.namespace.newName(name + "_zero"))
      List(node, oneCover, zeroCover)
    }
    (stmts, List())
  }

}
