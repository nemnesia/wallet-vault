package dev.vault.prototype
import org.junit.Assert.*
import org.junit.Test
class OperationGateTest {
    @Test fun cancelledCallbacksCannotFinishANewerOperation() {
        val gate = OperationGate();val old = gate.start();assertTrue(gate.current(old))
        gate.cancel();val fresh = gate.start();assertFalse(gate.current(old))
        gate.finish(old);assertTrue(gate.busy);assertTrue(gate.current(fresh))
        gate.finish(fresh);assertFalse(gate.busy)
    }
    @Test fun rejectsConcurrentAuthentication() {
        val gate = OperationGate();gate.start()
        try { gate.start();fail("expected BUSY") } catch(error:IllegalStateException) { assertEquals("BUSY",error.message) }
    }
}
