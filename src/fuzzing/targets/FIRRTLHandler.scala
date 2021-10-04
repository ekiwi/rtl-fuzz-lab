// Copyright 2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Kevin Laeufer <laeufer@cs.berkeley.edu>

package fuzzing.targets

import fuzzing.pass
import chiseltest._
import firrtl.options.{Dependency, TargetDirAnnotation}
import firrtl.stage.{FirrtlCircuitAnnotation, FirrtlFileAnnotation, FirrtlStage, RunFirrtlTransformAnnotation}
import firrtl.{AnnotationSeq, LowFirrtlEmitter}

object FIRRTLHandler {
  val DefaultAnnotations = Seq(
    RunFirrtlTransformAnnotation(Dependency(pass.MuxToggleCoverage)),
    RunFirrtlTransformAnnotation(Dependency(pass.MetaResetPass)),
    RunFirrtlTransformAnnotation(Dependency(pass.RemovePrintfPass)),
    RunFirrtlTransformAnnotation(Dependency(pass.AssertSignalPass)),
    RunFirrtlTransformAnnotation(Dependency[LowFirrtlEmitter]),
    // debugging output
    // LogLevelAnnotation(LogLevel.Info),
  )

  def firrtlToTarget(target: String, targetDir: String, annos: AnnotationSeq = Seq.empty): FuzzTarget = {
    val state = loadFirrtl(targetDir, annos)
    val info = TopmoduleInfo(state.circuit)
    //val dut = TreadleBackendAnnotation.getSimulator.createContext(state)
    val dut = VerilatorBackendAnnotation.getSimulator.createContext(state)

    val fuzzTarget: FuzzTarget = target.toLowerCase() match {
      case "rfuzz" => new RfuzzTarget(dut, info)
      case "tlul"  => new TLULTarget(dut, info)
      case other   => throw new NotImplementedError(s"Unknown target $other")
    }
    fuzzTarget
  }

  private lazy val firrtlStage = new FirrtlStage
  private def loadFirrtl(targetDir: String, annos: AnnotationSeq): firrtl.CircuitState = {
    // we need to compile the firrtl file to low firrtl + add mux toggle coverage and meta reset
    val allAnnos = DefaultAnnotations ++ Seq(TargetDirAnnotation(targetDir)) ++ annos
    val r = firrtlStage.execute(Array(), allAnnos)
    val circuit = r.collectFirst { case FirrtlCircuitAnnotation(c) => c }.get
    firrtl.CircuitState(circuit, r)
  }
}
