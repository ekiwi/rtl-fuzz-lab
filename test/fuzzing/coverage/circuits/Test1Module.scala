// SPDX-License-Identifier: Apache-2.0

package fuzzing.coverage.circuits

import chisel3._

class Test1Module(withSubmodules: Boolean = false) extends Module {
  val a = IO(Input(UInt(3.W)))
  val b = IO(Output(UInt(3.W)))

  b := 0.U // line 5

  when(a === 4.U) {
    b := 1.U
  }

  when(5.U < a) {
    b := 2.U
  }.otherwise {
    b := 3.U
  }

  when(a === 0.U) {
    chisel3.experimental.verification.cover(true.B, "user coverage")
  }

  when(a === 1.U) {
    // empty
  }

  // name collision for the cover chain generator
  val cover_chain_en = RegInit(0.U(3.W))
  cover_chain_en := a

  if(withSubmodules) {
    val c0 = Module(new SubModule1).suggestName("c0")
    c0.a := a
    val c1 = Module(new SubModule1).suggestName("c1")
    c1.a := a - 4.U
  }
}

class SubModule1 extends Module {
  val a = IO(Input(UInt(3.W)))
  chisel3.experimental.verification.cover(a > 4.U, "user coverage 2")
}
