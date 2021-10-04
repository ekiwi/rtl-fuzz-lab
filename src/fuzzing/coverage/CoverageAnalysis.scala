package fuzzing.coverage

import fuzzing.afl.MuxToggleOpAnnotation
import fuzzing.targets.{FIRRTLHandler, FuzzTarget}
import chiseltest.WriteVcdAnnotation
import firrtl.annotations.{Annotation, CircuitTarget}

object CoverageAnalysis extends App {
  var targetAnnos = Seq[Annotation]()
  targetAnnos = Seq[Annotation](
    DoNotCoverAnnotation(CircuitTarget("TLI2C").module("TLMonitor_72")),
    DoNotCoverAnnotation(CircuitTarget("TLI2C").module("DummyPlusArgReader_75"))
  )
  targetAnnos = targetAnnos ++ Seq(MuxToggleOpAnnotation(false))

  val writeVCD = false
  if (writeVCD) {
    targetAnnos = targetAnnos ++ Seq(WriteVcdAnnotation)
  }

  val targetKind = args(2)
  val target: FuzzTarget = FIRRTLHandler.firrtlToTarget(targetKind, "test_run_dir/" + targetKind + "_with_afl", targetAnnos)


  val outFolder = os.pwd / os.RelPath(args(1))
  val queue = outFolder / os.RelPath("queue")
  val end_time_file = outFolder / os.RelPath("end_time")
  val outputJSON = outFolder / os.RelPath("coverage.json")


  println("Generating coverage from provided inputs. Output to file " + outputJSON)

  //Read in inputs files from queue and generate list of input-coverage pairs (ignores invalid coverage)
  val queue_files = os.list(queue).filter(os.isFile)
  var invalid_files: Int = 0

  val files_coverageCounts = queue_files.flatMap { inputFile =>
    val in = os.read.inputStream(inputFile)
    val (coverage, valid) = target.run(in)
    in.close()

    if (valid) {
      Some((inputFile, coverage))
    } else {
      invalid_files += 1
      None
    }
  }

  //Prints proportion of invalid files
  assert(invalid_files / queue_files.length != 1, s"""No inputs in ${queue} are valid!""")
  println(s"""Proportion of invalid files is ${invalid_files}/${queue_files.length}""")

  //Builds JSON file from coverage data
  val out = new StringBuilder("{")
  appendCoverageData(out)
  out.append(", \n")
  appendEndTime(out)
  out.append("}")
  os.write.over(outputJSON, out.substring(0))

  println("Done!")

  //Append end time to JSON file
  def appendEndTime(out: StringBuilder): Unit = {
    val source = scala.io.Source.fromFile(end_time_file.toString())
    val data = try source.mkString.toLong finally source.close()

    assert(start_time != 0L, "Start time is not initialized")
    out.append(s""""end_time": ${(data - start_time) / 1000.0}""")
  }

  private var start_time = 0L

  //Append coverage data to JSON file
  def appendCoverageData(out: StringBuilder): Unit = {
    var overallCoverage = Set[Int]()
    var previous_time = 0L

    out.append(s""""coverage_data": \n[""")

    val filesCovIter = files_coverageCounts.iterator
    while (filesCovIter.hasNext) {
      val (file, count) = filesCovIter.next()

      out.append("\t{")

      //Add filename to JSON file
      val input_name = file.toString.split("/").last
      out.append(s""""filename": "${input_name}", """)

      //Add relative creation time (seconds) to JSON file
      val creation_time = file.toString().split(',').last.toLong
      if (input_name.split(',')(0) == "id:000000") {
        start_time = creation_time
      }
      assert(creation_time >= previous_time, "Input creation times are not monotonically increasing")
      previous_time = creation_time

      val relative_creation_time = (creation_time - start_time) / 1000.0
      out.append(s""""creation_time": ${relative_creation_time.toString}, """)

      //Add newly covered points to current set of covered points.
      overallCoverage = overallCoverage.union(processMuxToggleCoverage(count))
      //Calculate total coverage reached cumulatively up to now. Add cumulative coverage to JSON file
      val coverPoints = count.size //TODO: This needs to be divided by 2 when using PseudoMuxToggleCoverage. Handle this?
      val cumulativeCoverage = overallCoverage.size.toDouble / coverPoints
      out.append(s""""cumulative_coverage": ${cumulativeCoverage.toString}""")

      out.append("}")

      if (cumulativeCoverage == 1.0 && filesCovIter.hasNext) {
        println(s"""Cumulative coverage reached 100% early. Stopping on file: $input_name""")
        return
      }

      if (filesCovIter.hasNext) {
        out.append(", \n")
      }
    }
    out.append("\n]")
  }

  //Handles MuxToggleCoverage. Converts COUNTS (number of times each signal toggled) to
  // COVEREDPOINTS (the set of signals which have been toggled for this input)
  def processMuxToggleCoverage(counts: Seq[Byte]): Set[Int] = {
    var coveredPoints = Set[Int]()
    for (i <- counts.indices) {
      if (counts(i) >= 1) {
        coveredPoints += i
      }
    }
    coveredPoints
  }

  //Handles PseudoMuxToggleCoverage. Converts COUNTS (number of times each signal is on or off for the given input)
  // to COVEREDPOINTS (the set of signals which were both on and off for the given input)
  def processPseudoMuxToggleCoverage(counts: Seq[Byte]): Set[Int] = {
    var coveredPoints = Set[Int]()
    for (i <- 0 until counts.length / 2) {
      if (counts(i * 2) >= 1 && counts(i * 2 + 1) >= 1) {
        coveredPoints += i
      }
    }
    coveredPoints
  }

}
