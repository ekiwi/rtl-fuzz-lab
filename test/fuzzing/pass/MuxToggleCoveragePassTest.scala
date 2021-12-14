package fuzzing.pass

import fuzzing.afl.MuxToggleOpAnnotation
import chiseltest.WriteVcdAnnotation
import chiseltest.simulator._
import firrtl.LowFirrtlEmitter
import firrtl.options.{Dependency, TargetDirAnnotation}
import firrtl.stage.{FirrtlCircuitAnnotation, FirrtlSourceAnnotation, FirrtlStage, RunFirrtlTransformAnnotation}
import org.scalatest.flatspec.AnyFlatSpec

class MuxToggleCoveragePassTest extends AnyFlatSpec {
  private val testSrc =
    """circuit test :
      |  module test :
      |    input clock : Clock
      |    input reset : UInt<1>
      |    input cond: UInt<1>
      |    output out: UInt<32>
      |
      |    out <= UInt(7)
      |    when cond :
      |      out <= UInt(8)
      |""".stripMargin

  // we run all the passes to ensure they do not negatively interact with each other
  val DefaultAnnotations = Seq(
    RunFirrtlTransformAnnotation(Dependency(MuxToggleCoverage)),
    RunFirrtlTransformAnnotation(Dependency(MetaResetPass)),
    RunFirrtlTransformAnnotation(Dependency(RemovePrintfPass)),
    RunFirrtlTransformAnnotation(Dependency(AssertSignalPass)),
    RunFirrtlTransformAnnotation(Dependency[LowFirrtlEmitter]),
  )

  private val firrtlStage = new FirrtlStage
  private def load(name: String, src: String, fullMuxToggle: Boolean, vcd: Boolean = false): SimulatorContext = {
    var annos = DefaultAnnotations ++ Seq(TargetDirAnnotation("test_run_dir/" + name), FirrtlSourceAnnotation(src))
    annos = annos ++ Seq(MuxToggleOpAnnotation(fullMuxToggle))
    val r = firrtlStage.execute(Array(), annos)
    val circuit = r.collectFirst { case FirrtlCircuitAnnotation(c) => c }.get
    val state = firrtl.CircuitState(circuit, r ++ (if(vcd) Some(WriteVcdAnnotation) else None))
    // println(state.circuit.serialize)
    val dut = TreadleBackendAnnotation.getSimulator.createContext(state)
    dut
  }


  it should "MTC, short and long toggle" in {
    val dut = load("MTC_short_and_long", testSrc, false, vcd = true)

    val signal_values = List((1,1,0), (0,0,0), (0,1,1), (0,0,2), (0,0,2), (0,1,3), (0,1,3), (0,0,4))
    signal_values.foreach{ case (reset, cond, cov) =>
      dut.poke("reset", reset)
      dut.poke("cond", cond)
      dut.step(1)

      // println(dut.getCoverage())
      assert(dut.getCoverage().head._2 == cov)
    }
    dut.finish()
  }

  it should "FullMTC, short and long toggle" in {
    val dut = load("FullMTC_short_and_long", testSrc, true, vcd = true)

    val signal_values = List((1,1,0), (0,0,0), (0,1,0), (0,0,1), (0,0,1), (0,1,1), (0,1,1), (0,0,2))
    signal_values.foreach{ case (reset, cond, cov) =>
      dut.poke("reset", reset)
      dut.poke("cond", cond)
      dut.step(1)

      // println(dut.getCoverage())
      assert(dut.getCoverage().head._2 == cov)
    }
    dut.finish()
  }

  it should "FullMTC, toggle off" in {
    val dut = load("FullMTC_toggle_off", testSrc, true, vcd = true)

    val signal_values = List((1,1,0), (0,1,0), (0,0,0), (0,0,0), (0,1,1), (0,1,1), (0,1,1), (0,1,1))
    signal_values.foreach{ case (reset, cond, cov) =>
      dut.poke("reset", reset)
      dut.poke("cond", cond)
      dut.step(1)

      // println(dut.getCoverage())
      assert(dut.getCoverage().head._2 == cov)
    }
    dut.finish()
  }


  it should "FullMTC, should not count" in {
    val dut = load("FullMTC_should_not_count", testSrc, true, vcd = true)

    val signal_values = List((1,1,0), (0,1,0), (0,1,0), (0,1,0), (0,0,0), (0,0,0), (0,0,0), (0,0,0))
    signal_values.foreach{ case (reset, cond, cov) =>
      dut.poke("reset", reset)
      dut.poke("cond", cond)
      dut.step(1)

      // println(dut.getCoverage())
      assert(dut.getCoverage().head._2 == cov)
    }
    dut.finish()
  }

}
