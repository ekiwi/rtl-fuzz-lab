package fuzzing.afl

import firrtl.AnnotationSeq
import firrtl.annotations.NoTargetAnnotation
import firrtl.options.{DuplicateHandling, ExceptOnError, ShellOption}
import firrtl.stage.FirrtlSourceAnnotation
import fuzzing.annotations.MuxToggleOpAnnotation
import scopt.OptionParser
import chiseltest.WriteVcdAnnotation

case class Harness(name: String) extends NoTargetAnnotation
case object Directed extends NoTargetAnnotation
case class FeedbackCap(cap: Int) extends NoTargetAnnotation

class FuzzingArgumentParser extends OptionParser[AnnotationSeq]("fuzzer") with DuplicateHandling with ExceptOnError {

  private val arguments = Seq(
    //FIRRTL TODO: Can replace this with --firrtl-source already implemented?
    new ShellOption[String](
      longOption = "FIRRTL",
      toAnnotationSeq = input => Seq(FirrtlSourceAnnotation(input)),
      helpText = "",
      helpValueName = Some("<str>")
    ),
    //Harness
    new ShellOption[String](
      longOption = "Harness",
      toAnnotationSeq = input => Seq(Harness(input)),
      helpText = "",
      helpValueName = Some("<str>")
    ),
    //Directedness
    new ShellOption[Unit](
      longOption = "Directedness",
      toAnnotationSeq = _ => Seq(Directed),
      helpText = ""
    ),
    //VCD
    new ShellOption[Unit](
      longOption = "VCD",
      toAnnotationSeq = _ => Seq(WriteVcdAnnotation),
      helpText = "",
    ),
    //Feedback cap
    new ShellOption[Int](
      longOption = "Feedback",
      toAnnotationSeq = input => Seq(FeedbackCap(input)),
      helpText = "",
      helpValueName = Some("<i>")
    ),
    //MuxToggleCoverage
    new ShellOption[Unit](
      longOption = "Feedback",
      toAnnotationSeq = _ => Seq(MuxToggleOpAnnotation(true)),
      helpText = "",
      helpValueName = Some("<i>")
    ),
  )

  arguments.foreach(_.addOption(this))
  this.help("help").text("prints this usage text")
}
