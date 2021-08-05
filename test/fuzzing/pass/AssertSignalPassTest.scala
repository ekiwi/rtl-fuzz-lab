package fuzzing.pass

import chiseltest.{TreadleBackendAnnotation, WriteVcdAnnotation}
import chiseltest.simulator.{SimulatorContext, TreadleSimulator}
import firrtl.LowFirrtlEmitter
import firrtl.options.{Dependency, TargetDirAnnotation}
import firrtl.stage.{FirrtlCircuitAnnotation, FirrtlSourceAnnotation, FirrtlStage, RunFirrtlTransformAnnotation}
import org.scalatest.flatspec.AnyFlatSpec

class AssertSignalPassTest extends AnyFlatSpec {
  private val testSrc =
    """circuit test :
      |  module test :
      |    input clock : Clock
      |    input reset : UInt<1>
      |    input en: UInt<1>
      |    input a : UInt<32>
      |
      |    ; new style assert
      |    when and(not(reset), en) :
      |      assert(clock, not(eq(a, UInt(123))), UInt(1), " ") : new_style
      |
      |    ; old style assert
      |    when and(not(reset), and(en, eq(a, UInt(1234)))) :
      |      printf(clock, UInt(1), "Assertion failed") @[Monitor.scala 33:12]
      |      stop(clock, UInt(1), 1) : old_style @[Monitor.scala 33:12]
      |""".stripMargin

  // we run all the passes to ensure they do not negatively interact with each other
  val DefaultAnnotations = Seq(
    RunFirrtlTransformAnnotation(Dependency(MuxToggleCoverage)),
    RunFirrtlTransformAnnotation(Dependency(MetaResetPass)),
    RunFirrtlTransformAnnotation(Dependency(RemovePrintfPass)),
    RunFirrtlTransformAnnotation(Dependency(AssertSignalPass)),
    RunFirrtlTransformAnnotation(Dependency[LowFirrtlEmitter])
  )

  private val firrtlStage = new FirrtlStage
  private def load(name: String, src: String, vcd: Boolean = false): SimulatorContext = {
    val annos = DefaultAnnotations ++ Seq(TargetDirAnnotation("test_run_dir/" + name), FirrtlSourceAnnotation(src))
    val r = firrtlStage.execute(Array(), annos)
    val circuit = r.collectFirst { case FirrtlCircuitAnnotation(c) => c }.get
    val state = firrtl.CircuitState(circuit, r ++ (if(vcd) Some(WriteVcdAnnotation) else None))
    // println(state.circuit.serialize)
    val dut = TreadleBackendAnnotation.getSimulator.createContext(state)
    dut
  }

  it should "correctly translate circuits with old/new style asserts" in {
    val dut = load("AssertSignalPass_should_support_old_new_style_asserts", testSrc)
    dut.poke("reset", 0)
    dut.poke("en", 1)
    dut.poke("a", 123)
    assert(dut.peek("assert_failed") == 1)
    dut.poke("en", 0)
    assert(dut.peek("assert_failed") == 0)
    dut.poke("a", 1234)
    assert(dut.peek("assert_failed") == 0)
    dut.poke("en", 1)
    assert(dut.peek("assert_failed") == 1)
  }

  private val submoduleTestSrc =
    """circuit test :
      |  module child :
      |    input clock: Clock
      |    input reset: UInt<1>
      |    input a : UInt<32>
      |
      |    ; new style assert
      |    when not(reset) :
      |      assert(clock, not(eq(a, UInt(123))), UInt(1), " ") : new_style
      |
      |    ; old style assert
      |    when and(not(reset), eq(a, UInt(1234))) :
      |      printf(clock, UInt(1), "Assertion failed") @[Monitor.scala 33:12]
      |      stop(clock, UInt(1), 1) : old_style @[Monitor.scala 33:12]
      |
      |  module test :
      |    input clock : Clock
      |    input reset : UInt<1>
      |    input a : UInt<32>
      |
      |    inst c0 of child
      |    inst c1 of child
      |    c0.clock <= clock
      |    c0.reset <= reset
      |    c1.clock <= clock
      |    c1.reset <= reset
      |    c0.a <= a
      |    c1.a <= sub(a, UInt(6))
      |
      |    ; new style assert
      |    assert(clock, not(eq(a, UInt(6))), not(reset), "")
      |
      |""".stripMargin

  it should "correctly translate circuits with old/new style asserts + submodules" in {
    val withVCD = false
    val dut = load("AssertSignalPass_should_support_old_new_style_asserts_with_submodules", submoduleTestSrc,
      vcd = withVCD)
    val failValues = Seq(6, 123, 123 + 6, 1234, 1234 + 6)
    dut.poke("reset", 0)
    try {
      (0 until 2000).foreach { i =>
        dut.poke("a", i)
        dut.step(1) // just for a better VCD!
        val expected = if (failValues.contains(i)) 1 else 0
        assert(dut.peek("assert_failed") == expected, s"a=$i, expected $expected")
      }
    } catch {
      case e: Throwable =>
        dut.finish() // this is necessary for treadle to print the VCD
        throw e
    }
  }

}
