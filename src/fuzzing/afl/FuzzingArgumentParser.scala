package fuzzing.afl

import firrtl.AnnotationSeq
import firrtl.annotations.NoTargetAnnotation
import firrtl.options.{DuplicateHandling, ExceptOnError, ShellOption}
import firrtl.stage.FirrtlSourceAnnotation
import scopt.OptionParser
import treadle.WriteVcdAnnotation

case class Harness(name: String) extends NoTargetAnnotation
case object Directed extends NoTargetAnnotation
case class FeedbackCap(cap: String) extends NoTargetAnnotation

class FuzzingArgumentParser extends OptionParser[AnnotationSeq]("fuzzer") with DuplicateHandling with ExceptOnError {

  private val options = Seq(
    //FIRRTL TODO: Can replace this with --firtl-source already implemented?
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
    new ShellOption[String](
      longOption = "Directedness",
      toAnnotationSeq = _ => Seq(Directed),
      helpText = "",
      helpValueName = Some("<str>")
    ),
    //VCD
    new ShellOption[String](
      longOption = "VCD",
      toAnnotationSeq = _ => Seq(WriteVcdAnnotation),
      helpText = "",
      helpValueName = Some("<str>")
    ),
    //Feedback cap
    new ShellOption[String](
      longOption = "Feedback",
      toAnnotationSeq = input => Seq(FeedbackCap(input)),
      helpText = "",
      helpValueName = Some("<str>")
    ),



  )

  options.foreach(_.addOption(this))
  this.help("help").text("prints this usage text")
}
