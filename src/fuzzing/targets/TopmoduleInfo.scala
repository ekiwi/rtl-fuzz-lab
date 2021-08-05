package fuzzing.targets

import firrtl._

// TODO: replace with implementation from chiseltest, once that one becomes public
case class TopmoduleInfo(
  name:    String,
  inputs:  Seq[(String, Int)],
  outputs: Seq[(String, Int)],
  clocks:  Seq[String]) {
  require(inputs.forall(_._2 > 0), s"Inputs need to be at least 1-bit!\n$inputs")
  require(outputs.forall(_._2 > 0), s"Outputs need to be at least 1-bit!\n$outputs")
  def portNames: Seq[String] = inputs.map(_._1) ++ outputs.map(_._1) ++ clocks
}

object TopmoduleInfo {
  def apply(circuit: ir.Circuit): TopmoduleInfo = {
    val main = circuit.modules.find(_.name == circuit.main).get

    // extract ports
    // clock outputs are treated just like any other output
    def isClockIn(p: ir.Port): Boolean = p.tpe == ir.ClockType && p.direction == ir.Input
    val (clock, notClock) = main.ports.partition(isClockIn)
    val (in, out) = notClock.filterNot(p => bitWidth(p.tpe) == 0).partition(_.direction == ir.Input)

    new TopmoduleInfo(
      name = main.name,
      inputs = in.map(portNameAndWidth),
      outputs = out.map(portNameAndWidth),
      clocks = clock.map(_.name)
    )
  }

  private def portNameAndWidth(p: ir.Port): (String, Int) = {
    require(
      p.tpe.isInstanceOf[ir.GroundType],
      s"Port ${p.serialize} is not of ground type! Please make sure to provide LowFirrtl to this API!"
    )
    p.name -> bitWidth(p.tpe).toInt
  }
}
