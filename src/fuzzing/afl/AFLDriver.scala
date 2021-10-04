/*
 * Copyright (c) 2017-2021 The Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package fuzzing.afl

import fuzzing.coverage.DoNotCoverAnnotation
import fuzzing.targets.{FIRRTLHandler, FuzzTarget}
import chiseltest.WriteVcdAnnotation
import firrtl.annotations.{Annotation, CircuitTarget}
import firrtl.stage.FirrtlSourceAnnotation

import java.io.{File, InputStream, OutputStream, PrintWriter}

/** Provides a main function that can be used to interface with the AFL fuzzer.
  *
  *  Based on code written by Rohan Padhye and Caroline Lemieux for the JQF project
  */
object AFLDriver extends App {
  val parser = new FuzzingArgumentParser
  val argAnnos = parser.parse(args, Seq()).get
  var targetAnnos = Seq[Annotation]()

  //Parse args
  val targetKind = argAnnos.collectFirst {case Harness(i) => i}.getOrElse("")
  if (argAnnos.contains(Directed)) {
    targetAnnos = targetAnnos ++ Seq[Annotation](
      DoNotCoverAnnotation(CircuitTarget("TLI2C").module("TLMonitor_72")),
      DoNotCoverAnnotation(CircuitTarget("TLI2C").module("DummyPlusArgReader_75"))
    )
  }
  targetAnnos = targetAnnos ++ argAnnos.collectFirst {case FirrtlSourceAnnotation(i) => FirrtlSourceAnnotation(i)}
  targetAnnos = targetAnnos ++ argAnnos.collectFirst {case WriteVcdAnnotation => WriteVcdAnnotation}
  targetAnnos = targetAnnos ++ argAnnos.collectFirst {case MuxToggleOpAnnotation(i) => MuxToggleOpAnnotation(i)}


  val target: FuzzTarget = FIRRTLHandler.firrtlToTarget(targetKind, "test_run_dir/" + targetKind + "_with_afl", targetAnnos)

  println("Ready to fuzz! Waiting for someone to open the fifos!")
  val (a2jPipe, j2aPipe, inputFile) = (os.pwd / "a2j", os.pwd / "j2a", os.pwd / "input")
  AFLProxy.fuzz(target, a2jPipe, j2aPipe, inputFile)
}

/** Communicates with the AFLProxy written by Rohan Padhye and Caroline Lemieux for the JQF project */
object AFLProxy {
  val CoverageMapSize = 1 << 16
  def fuzz(target: FuzzTarget, a2jPipe: os.Path, j2aPipe: os.Path, inputFile: os.Path): Unit = {
    // connect to the afl proxy
    val proxyInput = os.read.inputStream(a2jPipe)
    val proxyOutput = os.write.outputStream(j2aPipe)

    // fuzz
    try {
//      var overallCoverage = Set[Int]()                                                      //Hack to measure cumulative coverage realtime
//      var cumulativeCoverage = 0.0                                                          //Hack to measure cumulative coverage realtime

      while (waitForAFL(proxyInput)) {
        val in = os.read.inputStream(inputFile)
        val (coverage, _) = target.run(in)
        in.close()
        // println(s"Sending coverage feedback. ($coverage)")

//        overallCoverage = overallCoverage.union(processMuxToggleCoverage(coverage))         //Hack to measure cumulative coverage realtime
//        val coverPoints = coverage.size                                                     //Hack to measure cumulative coverage realtime
//        val thisCoverage = overallCoverage.size.toDouble / coverPoints                      //Hack to measure cumulative coverage realtime
//        if (thisCoverage > cumulativeCoverage) {                                            //Hack to measure cumulative coverage realtime
//          cumulativeCoverage = thisCoverage                                                 //Hack to measure cumulative coverage realtime
//          println(cumulativeCoverage.toString, System.currentTimeMillis()/100)              //Hack to measure cumulative coverage realtime
//        }                                                                                   //Hack to measure cumulative coverage realtime

        handleResult(proxyOutput, coverage.toArray)
      }
    } catch {
      case _: java.io.IOException =>
    }

    val end_time_outputFile = "temp_out/end_time"
    val pw = new PrintWriter(new File(end_time_outputFile))
    pw.write(s"""${System.currentTimeMillis()}""")
    pw.close()

    target.finish(verbose = true)
  }

  private def waitForAFL(proxyInput: InputStream): Boolean = {
    // Get a 4-byte signal from AFL
    val signal = new Array[Byte](4)
    val received = proxyInput.read(signal, 0, 4)
    received == 4
  }

  private def handleResult(proxyOutput: OutputStream, coverage: Array[Byte]): Unit = {
    require(coverage.length < CoverageMapSize)
    val result = Result.Success // TODO
    val status = Result.toStatus(result)
    writeInt(proxyOutput, status)
    // indicate how many bytes we are going to send + 1
    writeInt(proxyOutput, coverage.length + 1)
    // send one dummy byte to avoid the "No instrumentation detected" error from AFL
    proxyOutput.write(1)
    // send actual coverage bytes
    proxyOutput.write(coverage)
    proxyOutput.flush()
  }

  private def writeInt(out: OutputStream, value: Int): Unit = {
    val buf = java.nio.ByteBuffer.allocate(4)
    buf.order(java.nio.ByteOrder.LITTLE_ENDIAN)
    buf.putInt(value)
    out.write(buf.array())
  }
}

object Result extends Enumeration {
  val Success, Invalid, Failure, Timeout = Value
  def toStatus(v: Result.Value): Int = v match {
    case Success => 0
    case Invalid =>
      // For invalid inputs, we send a non-zero return status
      // in the second smallest byte, which is the program's return status
      // for programs that exit successfully
      1 << 8
    case Failure =>
      // For failure, the exit value is non-zero in LSB to simulate exit with signal
      6 // SIGABRT
    case Timeout =>
      // For timeouts, we mock AFL's behavior of having killed the target
      // with a SIGKILL signal
      9 // SIGKILL
  }
}
