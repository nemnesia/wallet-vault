import Foundation

func require(_ condition: Bool, _ message: String) {
    if !condition { fatalError(message) }
}

var gate = OperationGate()
let first = gate.begin()!
require(gate.begin() == nil, "Concurrent operation must be rejected")
require(!gate.complete(UUID()), "Unrelated callback must not consume pending operation")
require(gate.cancel(), "Cancellation must consume pending operation")
require(!gate.complete(first), "Callback after cancellation must be rejected")
let second = gate.begin()!
require(!gate.complete(first), "Old callback must not consume replacement operation")
require(gate.complete(second), "Current operation must complete")
require(!gate.complete(second), "Duplicate completion must be rejected")
require(!gate.cancel(), "Idle cancellation must be harmless")
print("PASS: concurrent, unrelated, cancelled, stale and duplicate callback rejection")
