package fuzzing

import firrtl.AnnotationSeq
import firrtl.annotations._
import firrtl.options.{DuplicateHandling, ExceptOnError, ShellOption}
//import fuzzing.annotations.{CoverageMetric, Directed, FIRRTL, FeedbackCap, GenerateVCD, Harness, Seed}
import org.scalatest.freespec.AnyFreeSpec
import scopt.OptionParser

//import scala.io.Source
case object OptionA extends NoTargetAnnotation
case class OptionB(i: Int) extends NoTargetAnnotation
case class OptionC(s: String) extends NoTargetAnnotation

class AnnotationExamples extends AnyFreeSpec {
  "check for the existence of an annotation" in {
    val annos = Seq(OptionA)
    assert(annos.contains(OptionA))

    assert(!Seq().contains(OptionA))
  }

  "find a value, return a default if not found" in {
    assert(Seq(OptionB(3), OptionA).collectFirst{ case OptionB(i) => i }.getOrElse(0) == 3)
    assert(Seq(OptionB(4), OptionB(3), OptionA).collectFirst{ case OptionB(i) => i }.getOrElse(0) == 4)
    assert(Seq(OptionA, OptionC("test")).collectFirst{ case OptionB(i) => i }.getOrElse(0) == 0)
  }

  "serialize to JSON" in {
    val annos = Seq(OptionC("test"), OptionB(24), OptionA)
    val json = JsonProtocol.serialize(annos)
    val expected =
      """[
        |  {
        |    "class":"fuzzing.OptionC",
        |    "s":"test"
        |  },
        |  {
        |    "class":"fuzzing.OptionB",
        |    "i":24
        |  },
        |  {
        |    "class":"fuzzing.OptionA$"
        |  }
        |]
        |""".stripMargin
    assert(json.trim == expected.trim)
  }

  "serialize to JSON, config file" in {
    //val annos = Seq(FIRRTL("test/resources/fuzzing/TLI2C.fir"), afl.Harness("tlul"), Seed("seeds/TLI2C_longSeed.hwf"),
      //CoverageMetric("MuxToggleCoverage"), Directed(true), FeedbackCap(1), GenerateVCD(false))

    //val json = JsonProtocol.serialize(annos)
    //print(json)
  }


  "parse from JSON" in {
    val json =
      """[{"class": "fuzzing.OptionA$"},
        |{"class": "fuzzing.OptionC", "s": "test bla bla"},
        |{"class": "fuzzing.OptionB", "i": -100}]
        |""".stripMargin
    val annos = JsonProtocol.deserialize(json)
    assert(annos.contains(OptionA))
    assert(annos.collectFirst{ case OptionB(i) => i}.getOrElse(0) == -100)
    assert(annos.collectFirst{ case OptionC(s) => s}.getOrElse("") == "test bla bla")
  }

  "parse from JSON, config file" in {
    //val file = Source.fromFile("config.json")
    //val json = file.getLines.mkString
    //file.close
    //val annos = JsonProtocol.deserialize(json)
    //print(annos)
  }

  "parse command line arguments" in {
    val options = Seq(
      new ShellOption[Unit](
        longOption = "option-a",
        toAnnotationSeq = _ => Seq(OptionA),
        helpText = "set the option A flag"
      ),
      new ShellOption[String](
        longOption = "option-c",
        toAnnotationSeq = a => Seq(OptionC(a)),
        helpText = "set option-c with string <str>",
        helpValueName = Some("<str>")
      ),
      new ShellOption[Int](
        longOption = "option-b",
        toAnnotationSeq = a => Seq(OptionB(a)),
        helpText = "set option-b with int <i>",
        helpValueName = Some("<i>")
      ),
    )

    // create the parser
    val parser = new OptionParser[AnnotationSeq]("fuzzer") with DuplicateHandling with ExceptOnError
    options.foreach(_.addOption(parser))
    parser.help("help").text("prints this usage text")

    // this will print to stdout
    // parser.parse(Seq("--help"), Seq())

    // the second argument to parse are the inputs annotations
    val annos = parser.parse(Seq("--option-a", "--option-c", "test 321", "--option-b", "12345", "--option-c", "test 123"), Seq(OptionA)).get
    assert(annos.count(_ == OptionA) == 2)
    assert(annos.collectFirst{ case OptionB(i) => i}.getOrElse(0) == 12345)
    assert(annos.collectFirst{ case OptionC(s) => s}.getOrElse("") == "test 123")
    assert(annos.collect{ case OptionC(s) => s} == Seq("test 123", "test 321"))
  }

}
