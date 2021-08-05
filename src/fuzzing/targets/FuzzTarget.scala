// Copyright 2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Kevin Laeufer <laeufer@cs.berkeley.edu>

package fuzzing.targets

/** A common interface for a fuzzing target. */
trait FuzzTarget {
  def run(input: java.io.InputStream): (Seq[Byte], Boolean)
  def finish(verbose: Boolean = false): Unit // clean up
}
