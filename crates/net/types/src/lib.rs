enum NetMessage {
    Garb(GarbMessage),
    Eval(EvalMessage),
}

enum GarbMessage {
    Service(GarbSvcMessage),
    Protocol(GarbProtocolMessage),
}

/// Mosaic service messages
enum GarbSvcMessage {
    /// We are starting a garbling table transfer.
    StartingGarbTableTransfer(GarbTableCommitment),
    /// Ordered chunk of garbling table
    GarbTableChunk(GarbTableChunk),
}

enum GarbProtocolMessage {
    // protocol messages from the Garbler state machine...
}

enum EvalMessage {
    AcceptGarbTable(GarbTableCommitment),
}
