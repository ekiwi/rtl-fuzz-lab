package fuzzing

import firrtl.stage.FirrtlFileAnnotation
import fuzzing.targets.FIRRTLHandler
import org.scalatest.flatspec.AnyFlatSpec

import java.io.ByteArrayInputStream

class RfuzzTargetTests extends AnyFlatSpec {
  behavior of "RfuzzTarget"

  val target = "rfuzz"

  it should "execute a single input" in {
    val fuzzer = FIRRTLHandler.firrtlToTarget(target, "test_run_dir/rfuzz", Seq(FirrtlFileAnnotation("test/resources/fuzzing/TLI2C.fir")))
    val input = Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0).map(_.toByte)
    val (coverage, _) = fuzzer.run(new ByteArrayInputStream(input), 1)
    println(coverage)
    fuzzer.finish()
  }

}
