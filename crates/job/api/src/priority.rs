//! Job priority levels.
//!
//! Priority maps protocol phases to urgency. The heavy pool drains
//! higher-priority queues first; the garbling coordinator orders its
//! backlog by priority so a withdrawal-dispute evaluation is selected
//! ahead of setup work.

/// Priority level for job execution.
///
/// Maps to protocol phases with different urgency:
/// - **Critical**: Withdrawal disputes with blockchain timeouts
/// - **High**: Active deposit processing
/// - **Normal**: Setup operations done in advance
///
/// The derived order sorts by urgency: `Critical < High < Normal`, so an
/// ascending sort puts the most urgent work first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Priority {
    /// Withdrawal dispute resolution — blockchain timeout at stake.
    ///
    /// Actions: `CompleteAdaptorSignatures`, `EvaluateGarblingTable`
    Critical = 0,

    /// Active deposit processing — user waiting.
    ///
    /// Actions: `DepositGenerateAdaptors`, `DepositVerifyAdaptors`
    High = 1,

    /// Setup operations — can be done in advance, no urgency.
    ///
    /// Actions: `GeneratePolynomialCommitments`, `GenerateShares`,
    /// `VerifyOpenedInputShares`
    Normal = 2,
}

impl Priority {
    /// Returns `true` if this priority is higher than `other`.
    pub fn is_higher_than(self, other: Self) -> bool {
        // Lower discriminant = higher priority.
        (self as u8) < (other as u8)
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Normal => write!(f, "normal"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_matches_urgency() {
        assert!(Priority::Critical < Priority::High);
        assert!(Priority::High < Priority::Normal);
        assert!(Priority::Critical.is_higher_than(Priority::Normal));
        assert!(!Priority::Normal.is_higher_than(Priority::Critical));
    }
}
