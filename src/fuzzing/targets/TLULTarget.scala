// Copyright 2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Kevin Laeufer <laeufer@cs.berkeley.edu>

package fuzzing.targets

import chiseltest.simulator._

sealed abstract class Opcode(val value: Byte)
case object Invalid extends Opcode(0)
case object Wait extends Opcode(1)
case object Read extends Opcode(2)
case object Write extends Opcode(3)

object TLULOpcodeAChannel extends Enumeration {
  type TLULOpcodeAChannel = Value
  val PutFull = Value("0")
  val Get = Value("4")
}

//TODO: Consider cleaning up this logic using writeInt
case class Instruction(opcode: Opcode, address: BigInt = 0, data: BigInt = 0) {
  def toByteArray: Array[Byte] = {
    //OPCODE
    var byteArray = Array(opcode.value)

    if (opcode != Invalid && opcode != Wait) {
      //ADDRESS
      for (i <- 0 to 3) {
        val byte = Array(((address >> i * 8) & 0xff).toByte)
        byteArray ++= byte
      }

      if (opcode != Read) {
        //DATA
        for (i <- 0 to 3) {
          val byte = Array(((data >> i * 8) & 0xff).toByte)
          byteArray ++= byte
        }
      }

    }
    byteArray
  }
}

class TLULTarget(dut: SimulatorContext, info: TopmoduleInfo) extends FuzzTarget {

  private var TLprefix = "Error";
  for ((input, _) <- info.inputs) {
    println(input)
    if (input.endsWith("b_ready")) {
      TLprefix = input.take(input.length - 7)
    }
  }

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

  private def getCoverage(feedbackCap: Int): Seq[Byte] = {
    val c = dut.getCoverage()
    c.map(_._2).map(v => scala.math.min(v, feedbackCap).toByte)
  }

  //NEW CONSTANTS
  //Number of bits of data read in
  val OT_TL_DW = 32
  //Number of bytes needed for above number of bits
  val OT_TL_DBW = OT_TL_DW >> 3
  //Calculated number x such that 2^x can store above number of bytes
  val OT_TL_SZW: BigInt = math.ceil(math.log(OT_TL_DBW) / math.log(2)).toInt
  //Represents a mask for those bits which are read in (1 means read the bit, 0 means don't read it in)
  val FULL_MASK = (1 << OT_TL_DBW) - 1
  val DEV_RESPONSE_TIMEOUT = 100
  //NEW CONSTANTS

  private def Get(address: BigInt): BigInt = {
    SendTLULRequest(TLULOpcodeAChannel.Get.toString.toInt, address, 0, OT_TL_SZW, FULL_MASK)
    WaitForDeviceResponse()

    val d_data = dut.peek(TLprefix + "d_bits_data")
    ClearRequest()
    d_data
  }

  private def PutFull(address: BigInt, data: BigInt): Unit = {
    SendTLULRequest(TLULOpcodeAChannel.PutFull.toString.toInt, address, data, OT_TL_SZW, FULL_MASK)
    WaitForDeviceResponse()
    ClearRequest()
  }

  private def SendTLULRequest(opcode: BigInt, address: BigInt, data: BigInt, size: BigInt, mask: BigInt): Unit = {
    dut.poke(TLprefix + "a_valid", 1)
    dut.poke(TLprefix + "a_bits_opcode", opcode)
    dut.poke(TLprefix + "a_bits_size", size)
    dut.poke(TLprefix + "a_bits_address", address)
    dut.poke(TLprefix + "a_bits_data", data)
    dut.poke(TLprefix + "a_bits_mask", mask)
    dut.poke(TLprefix + "d_ready", 1)

    WaitForDeviceReady()
  }

  private def WaitForDeviceReady(): Unit = {
    step()
    WaitForDevice(TLprefix + "a_ready")
  }
  private def WaitForDeviceResponse(): Unit = {
    WaitForDevice(TLprefix + "d_valid")
  }
  private def WaitForDevice(port: String): Unit = {
    var timeout = DEV_RESPONSE_TIMEOUT
    while (dut.peek(port) == 0) {
      step()
      if (timeout == 0) {
        throw new Exception("TIMEOUT waiting for device")
      }
      timeout -= 1
    }
  }

  private val fuzzInputs = info.inputs.filterNot { case (n, _) => n == MetaReset || n == "reset" }
  private def ClearRequest(): Unit = {
    //fuzzInputs.foreach { case (name, size) => println("'" + name + "'", size.toString, dut.peek(name).toString) }
    //println("---")
    fuzzInputs.foreach { case (name, _) => dut.poke(name, 0) }
    dut.poke(TLprefix + "d_ready", 1)
  }

  private def applyInstruction(instruction: Instruction): Unit = {
    //println("Instruction is: " + instruction.toString)

    instruction.opcode match {
      case Wait => {
        step()
        //println("Wait")
      }
      case Read => {
        val readData = Get(instruction.address)
        //println("Read: " + readData.toString)
      }
      case Write => {
        PutFull(instruction.address, instruction.data)
        //println("Write: " + instruction.data.toString + " to address " + instruction.address.toString)
      }
      case _ => {
        //println("Invalid")
      }
    }
  }

  //VARIABLE SIZE VERSION: Only takes the necessary amount of bytes for the instruction
  //Returns next instruction, created by taking the next rightmost bits from input steam
  private def getInstruction(input: java.io.InputStream): (Instruction, Boolean) = {
    val (opcode, readValid): (Opcode, Boolean) = getOpcode(input)

    val ADDRESS_SIZE_BYTES = 4
    val DATA_SIZE_BYTES = 4

    if (!readValid) {
      (Instruction(Invalid), false)
    } else {
      var address: BigInt = 0
      var data:    BigInt = 0

      if (opcode == Read || opcode == Write) {
        val addressBytes: Array[Byte] = input.readNBytes(ADDRESS_SIZE_BYTES)
        if (addressBytes.length != ADDRESS_SIZE_BYTES) {
          return (Instruction(Invalid), false)
        }
        address = addressBytes.zipWithIndex.map { case (b, i) => BigInt(b) << (i * 8) }.reduce(_ | _)
      }

      if (opcode == Write) {
        val dataBytes: Array[Byte] = input.readNBytes(DATA_SIZE_BYTES)
        if (dataBytes.length != ADDRESS_SIZE_BYTES) {
          return (Instruction(Invalid), false)
        }
        data = dataBytes.zipWithIndex.map { case (b, i) => BigInt(b) << (i * 8) }.reduce(_ | _)
      }

      (Instruction(opcode, address, data), true)
    }
  }

  //CONSTANT VERSION: 3 values of byte correspond to valid opcodes, rest are invalid.
  private def getOpcode(input: java.io.InputStream): (Opcode, Boolean) = {
    val OPCODE_SIZE_BYTES = 1
    //Reads in next byte from input stream
    val opcodeByte: Array[Byte] = input.readNBytes(OPCODE_SIZE_BYTES)
    if (opcodeByte.length != OPCODE_SIZE_BYTES) {
      return (Invalid, false)
    }

    //Matches opcodeByte to corresponding opcodes (1-3). (0, 4-255) match to Invalid.
    val nextOpcode: Opcode = opcodeByte(0) match {
      case Wait.value  => Wait
      case Read.value  => Read
      case Write.value => Write
      case _           => Invalid
    }
    (nextOpcode, true)
  }

  //NEW METHODS

  override def run(input: java.io.InputStream, feedbackCap: Int): (Seq[Byte], Boolean) = {
    val start = System.nanoTime()
    setInputsToZero()
    metaReset()
    reset()
    isValid = true
    // we only consider coverage _after_ the reset is done!
    dut.resetCoverage()

    //TODO: Set d_ready to be 1, as is done in TLULHostTb initialization?
    dut.poke(TLprefix + "d_ready", 1)

    var instruction_readValid: (Instruction, Boolean) = getInstruction(input)
    //Loop if last readValid = true
    while (instruction_readValid._2) {
      applyInstruction(instruction_readValid._1)
      instruction_readValid = getInstruction(input)
    }

    val startCoverage = System.nanoTime()
    var c = getCoverage(feedbackCap)

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
