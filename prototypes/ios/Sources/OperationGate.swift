import Foundation

// No authentication result can complete an operation after cancellation or replacement.
struct OperationGate {
    private(set) var pending: UUID?

    mutating func begin() -> UUID? {
        guard pending == nil else { return nil }
        let id = UUID()
        pending = id
        return id
    }

    mutating func complete(_ id: UUID) -> Bool {
        guard pending == id else { return false }
        pending = nil
        return true
    }

    @discardableResult
    mutating func cancel() -> Bool {
        let wasPending = pending != nil
        pending = nil
        return wasPending
    }
}
