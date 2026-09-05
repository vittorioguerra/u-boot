/**
 * @name Network byte swap flows to memcpy
 * @id   network-byte-swap
 * @kind path-problem
 * @tags custom, taint
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mac |
      mac.getMacro().getName().matches("ntohl%") and
      this = mac.getExpr()
    )
  }
}

module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall memcpy |
      memcpy.getTarget().getName() = "memcpy" and
      sink.asExpr() = memcpy.getArgument(2)  // Terzo argomento di memcpy
    )
  }

  predicate isBarrier(DataFlow::Node barrier) {
    exists(IfStmt ifs |
      barrier.asExpr().getBasicBlock() = ifs
    )
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink)
select sink, source, sink, "network byte swap flows to memcpy"
