package fuzzing

import fuzzing.targets.FIRRTLHandler
import org.scalatest.flatspec.AnyFlatSpec

import java.io.ByteArrayInputStream

class RfuzzTargetTests extends AnyFlatSpec {
  behavior of "RfuzzTarget"

  val target = "rfuzz"

  it should "execute a single input" in {
    val fuzzer = FIRRTLHandler.firrtlToTarget("test/resources/fuzzing/TLI2C.fir", target, "test_run_dir/rfuzz")
    val input = Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0).map(_.toByte)
    val (coverage, _) = fuzzer.run(new ByteArrayInputStream(input))
    println(coverage)
    fuzzer.finish()
  }

}
