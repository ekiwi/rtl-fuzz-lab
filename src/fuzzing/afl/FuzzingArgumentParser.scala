package fuzzing.afl

import firrtl.AnnotationSeq
import firrtl.annotations.{CircuitTarget, NoTargetAnnotation}
import firrtl.options.{DuplicateHandling, ExceptOnError, ShellOption}
import firrtl.stage.FirrtlFileAnnotation
import scopt.OptionParser
import chiseltest.WriteVcdAnnotation
import fuzzing.coverage.DoNotCoverAnnotation

case class Harness(name: String) extends NoTargetAnnotation
case class FeedbackCap(cap: Int) extends NoTargetAnnotation
case class MuxToggleOpAnnotation(fullToggle: Boolean) extends NoTargetAnnotation


//Note: Currently doesn't extend native argument parser, may be useful later.
class FuzzingArgumentParser extends OptionParser[AnnotationSeq]("fuzzer") with DuplicateHandling with ExceptOnError {

  private val argumentOptions = Seq(
    new ShellOption[String](
      longOption = "FIRRTL",
      toAnnotationSeq = input => Seq(FirrtlFileAnnotation(input)),
      helpText = "",
      helpValueName = Some("<str>")
    ),
    new ShellOption[String](
      longOption = "Harness",
      toAnnotationSeq = input => Seq(Harness(input)),
      helpText = "",
      helpValueName = Some("<str>")
    ),
    new ShellOption[Boolean](
      longOption = "Directedness",
      toAnnotationSeq = input => if (input) {
                                      Seq(DoNotCoverAnnotation(CircuitTarget("TLI2C").module("TLMonitor_72")),
                                      DoNotCoverAnnotation(CircuitTarget("TLI2C").module("DummyPlusArgReader_75")),
                                      DoNotCoverAnnotation(CircuitTarget("TLSPI").module("TLMonitor_66")),
                                      DoNotCoverAnnotation(CircuitTarget("TLSPI").module("SPIFIFO_1")),
                                      DoNotCoverAnnotation(CircuitTarget("TLSPI").module("SPIMedia_1")),
                                      DoNotCoverAnnotation(CircuitTarget("TLSPI").module("DummyPlusArgReader_69")),
                                      DoNotCoverAnnotation(CircuitTarget("TLSPI").module("Queue_18")),
                                      DoNotCoverAnnotation(CircuitTarget("TLSPI").module("Queue_19")),
                                      DoNotCoverAnnotation(CircuitTarget("TLSPI").module("SPIPhysical_1")))
                                  } else {Seq()},
      helpText = ""
    ),
    new ShellOption[Boolean](
      longOption = "VCD",
      toAnnotationSeq = input => if (input) {Seq(WriteVcdAnnotation)} else {Seq()},
      helpText = "",
    ),
    new ShellOption[Int](
      longOption = "Feedback",
      toAnnotationSeq = input => Seq(FeedbackCap(input)),
      helpText = "",
      helpValueName = Some("<i>")
    ),
    new ShellOption[Boolean](
      longOption = "MuxToggleCoverage",
      toAnnotationSeq = input => Seq(MuxToggleOpAnnotation(input)),
      helpText = "",
      helpValueName = Some("<i>")
    ),
  )

  argumentOptions.foreach(_.addOption(this))
  this.help("help").text("prints this usage text")
}
