// Copyright 2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Kevin Laeufer <laeufer@cs.berkeley.edu>

package fuzzing.targets

import chiseltest.simulator._

class RfuzzTarget(dut: SimulatorContext, info: TopmoduleInfo) extends FuzzTarget {
  val MetaReset = "metaReset"
  require(info.clocks.size == 1, s"Only designs with a single clock are supported!\n${info.clocks}")
  require(info.inputs.exists(_._1 == MetaReset), s"No meta reset in ${info.inputs}")
  require(info.inputs.exists(_._1 == "reset"))

  private var isValid = true

  private val clock = info.clocks.head
  private def step(): Unit = {
    val assert_failed = dut.peek("assert_failed") == 1
    if (assert_failed) {
      isValid = false
    }

    dut.step(1)
    cycles += 1
  }
  private var cycles:       Long = 0
  private var resetCycles:  Long = 0
  private var totalTime:    Long = 0
  private var coverageTime: Long = 0

  private def setInputsToZero(): Unit = {
    info.inputs.foreach { case (n, _) => dut.poke(n, 0) }
  }

  private def metaReset(): Unit = {
    dut.poke(MetaReset, 1)
    step()
    dut.poke(MetaReset, 0)
    resetCycles += 1
  }

  private def reset(): Unit = {
    dut.poke("reset", 1)
    step()
    dut.poke("reset", 0)
    resetCycles += 1
  }

  private val inputBits = info.inputs.map(_._2).sum
  private val inputSize = scala.math.ceil(inputBits.toDouble / 8.0).toInt

  private val originalRFUZZinputSize = ((((inputBits + 7) / 8) + 8 - 1) / 8) * 8

  private def pop(input: java.io.InputStream): Array[Byte] = {
    val r = input.readNBytes(inputSize)
    if (r.size == inputSize) { r } else { Array.emptyByteArray }
  }

  private def popRFUZZ(input: java.io.InputStream): Array[Byte] = {
    val r = input.readNBytes(originalRFUZZinputSize)
    if (r.size == originalRFUZZinputSize) { r } else { Array.emptyByteArray }
  }

  private def getCoverage: Seq[Byte] = {
    dut.getCoverage().map(_._2).map(v => scala.math.min(v, 255).toByte)
  }

  private val fuzzInputs = info.inputs.filterNot { case (n, _) => n == MetaReset || n == "reset" }
  private def applyInputs(bytes: Array[Byte]): Unit = {
    var input: BigInt = bytes.zipWithIndex.map { case (b, i) => BigInt(b) << (i * 8) }.reduce(_ | _)
    fuzzInputs.foreach { case (name, bits) =>
      val mask = (BigInt(1) << bits) - 1
      val value = input & mask
      input = input >> bits
      println("'" + name + "'", bits.toString, value.toString)
      dut.poke(name, value)
    }
    println("---")
  }

  private def applyRfuzzInputs(bytes: Array[Byte]): Unit = {
    //Ordered Rfuzz inputs
    val sortedInputs = Seq[String]("auto_in_a_bits_data", "auto_in_c_bits_data", "auto_in_a_bits_address",
      "auto_in_c_bits_address", "auto_in_a_bits_source", "auto_in_c_bits_source", "auto_in_a_bits_mask", "auto_in_a_bits_opcode",
      "auto_in_a_bits_param", "auto_in_c_bits_opcode", "auto_in_c_bits_param", "auto_in_a_bits_size", "auto_in_c_bits_size",
      "auto_in_a_valid", "auto_in_b_ready", "auto_in_c_valid", "auto_in_c_bits_error", "auto_in_d_ready", "auto_in_e_valid",
      "auto_in_e_bits_sink", "io_port_scl_in", "io_port_sda_in")

    //Create sequence of (channel, bit size) tuples ordered by original RFUZZ ordering
    val channelNameToSize = fuzzInputs.map { input => (input._1, input._2) }.toMap
    val sortedTuples = sortedInputs.map { input => (input, channelNameToSize(input)) }

    //Iterate over bits and apply bits to dut
    var input: BigInt = bytes.reverse.zipWithIndex.map { case (b, i) => BigInt(b) << (i * 8) }.reduce(_ | _)
    sortedTuples.foreach { case (name, size) =>
      val shiftLength = originalRFUZZinputSize * 8 - size
      val mask = ((BigInt(1) << size) - 1) << shiftLength
      val bits = (input & mask) >> shiftLength
      dut.poke(name, bits)
      input = input << size
    }
  }

  override def run(input: java.io.InputStream): (Seq[Byte], Boolean) = {
    val start = System.nanoTime()
    setInputsToZero()
    metaReset()
    reset()
    isValid = true
    // we only consider coverage _after_ the reset is done!
    dut.resetCoverage()

    var inputBytes = pop(input)
    while (inputBytes.nonEmpty) {
      applyInputs(inputBytes)
      step()
      inputBytes = pop(input)
    }

    val startCoverage = System.nanoTime()
    var c = getCoverage

    if (!isValid && !acceptInvalid) {
      c = Seq.fill[Byte](c.length)(0)
    }

    val end = System.nanoTime()
    totalTime += (end - start)
    coverageTime += (end - startCoverage)
    (c, isValid)
  }

  private val acceptInvalid = false

  private def ms(i: Long): Long = i / 1000 / 1000
  override def finish(verbose: Boolean): Unit = {
    dut.finish()
    if (verbose) {
      println(s"Executed $cycles target cycles (incl. $resetCycles reset cycles).")
      println(s"Total time in simulator: ${ms(totalTime)}ms")
      println(s"Total time for getCoverage: ${ms(coverageTime)}ms (${coverageTime.toDouble / totalTime.toDouble * 100.0}%)")
      val MHz = cycles.toDouble * 1000.0 / totalTime.toDouble
      println(s"$MHz MHz")
    }
  }
}
