package fuzzing.annotations

import firrtl.annotations.{ModuleTarget, SingleTargetAnnotation}

/** Tags a module that should not have any coverage added.
  *  This annotation should be respected by all automated coverage passes.
  */
case class DoNotCoverAnnotation(target: ModuleTarget) extends SingleTargetAnnotation[ModuleTarget] {
  override def duplicate(n: ModuleTarget) = copy(target = n)
}
