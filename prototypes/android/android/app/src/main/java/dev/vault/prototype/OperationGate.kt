package dev.vault.prototype

internal class OperationGate {
    data class Token(val epoch: Long)
    private var epoch = 0L
    private var active: Token? = null
    val busy get() = active != null
    fun start(): Token {
        check(!busy) { "BUSY" }
        return Token(++epoch).also { active = it }
    }
    fun current(token: Token) = active === token && epoch == token.epoch
    fun finish(token: Token) { if (current(token)) active = null }
    fun cancel() { epoch++; active = null }
}
