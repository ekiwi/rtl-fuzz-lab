package fuzzing

import chiseltest.WriteVcdAnnotation
import firrtl.annotations.CircuitTarget
import firrtl.stage.FirrtlFileAnnotation
import fuzzing.afl.MuxToggleOpAnnotation
import fuzzing.coverage.DoNotCoverAnnotation
import fuzzing.targets.{FIRRTLHandler, Instruction, Read, Wait, Write}
import org.scalatest.flatspec.AnyFlatSpec

import java.io.ByteArrayInputStream

class TLULTargetTests extends AnyFlatSpec {
  behavior of "TLULTarget"

  val target = "TLUL"
  val VCD = Seq(WriteVcdAnnotation)
  val FIRRTL = Seq(FirrtlFileAnnotation("test/resources/fuzzing/TLI2C.fir"))
  val MTC = Seq(MuxToggleOpAnnotation(false))
  val Direct = Seq(
    DoNotCoverAnnotation(CircuitTarget("TLI2C").module("TLMonitor_72")),
    DoNotCoverAnnotation(CircuitTarget("TLI2C").module("DummyPlusArgReader_75"))
  )

  it should "execute a single input" in {
    val fuzzer = FIRRTLHandler.firrtlToTarget(target, "test_run_dir/TLUL_unit_test", FIRRTL)
    //21 bytes required to provide a complete TLI2C input (without HWF Grammar)
    val input = Array(1, 3, 0, 0, 0, 2, 3, 0, 0, 0, 2, 0, 0, 0, 2).map(_.toByte)
    val (coverage, _) = fuzzer.run(new ByteArrayInputStream(input), 1)
    println(coverage)
    fuzzer.finish()
  }

  it should "execute a single input, using grammar" in {
    val fuzzer = FIRRTLHandler.firrtlToTarget(target, "test_run_dir/TLUL_unit_test", FIRRTL)
    // the I2C peripheral base address is at 0x10016000
    val addr = 0x10016000L

    // try out some offsets
    val offsets = Seq(
      // these offsets seem to be OK (even though the I2C peripheral only uses a small fraction of them)
      // https://github.com/sifive/sifive-blocks/blob/master/src/main/scala/devices/i2c/I2CCtrlRegs.scala#L7
      0, 4, 8, 12, 16, 4 * 200,
      // this offset triggers the assertions
      4 * 2000,
    )


    // understanding the assertions:
    // - " 'A' channel carries [...] type unsupported by manager "
    //   this is actually related to the address being out of range for the peripheral!
    // - " 'A' channel [...] address not aligned to size "
    //   the address needs to be a multiple of 4

    val a = Instruction(Wait).toByteArray
    val b = Instruction(Write, addr, 1).toByteArray
    val c = Instruction(Read, addr).toByteArray
    val input = a ++ a ++ b ++ b ++ c ++ offsets.map(o => Instruction(Read, addr + o).toByteArray).reduce(_ ++ _)

    val (coverage, _) = fuzzer.run(new ByteArrayInputStream(input), 1)
    println(coverage)
    fuzzer.finish()
  }


  it should "execute an inputted file, tlul" in {
    val fuzzer = FIRRTLHandler.firrtlToTarget("tlul", "test_run_dir/TLUL_input_file", VCD ++ FIRRTL ++ MTC ++ Direct)

    //Read in generated input file as bytes
    //val inputPath = "seeds/auto_ecb_128bit_encrypt_2blocks.hwf"
    val inputPath = "src/fuzzing/template_seeds/binary/TLI2C_longSeed.hwf"
    val inputFile = os.pwd / os.RelPath(inputPath)
    val input = os.read.inputStream(inputFile)

    val (coverage, _) = fuzzer.run(input, 255)
    println(coverage)
    fuzzer.finish()
  }

  it should "execute an inputted file, rufzz" in {
    val fuzzer = FIRRTLHandler.firrtlToTarget("rfuzz", "test_run_dir/TLUL_input_file", VCD ++ FIRRTL ++ MTC ++ Direct)

    //Read in generated input file as bytes
    //val inputPath = "seeds/auto_ecb_128bit_encrypt_2blocks.hwf"
    val inputPath = "src/fuzzing/template_seeds/binary/RFUZZ_longSeed.hwf"
    val inputFile = os.pwd / os.RelPath(inputPath)
    val input = os.read.inputStream(inputFile)

    val (coverage, _) = fuzzer.run(input, 255)
    println(coverage)
    fuzzer.finish()
  }

}
