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

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
