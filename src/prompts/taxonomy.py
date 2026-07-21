from __future__ import annotations

DETECT_VULNERABILITY_TYPES = (
    "accounting-error",
    "price-manipulation",
    "access-control",
    "reentrancy",
    "input-validation",
)

# Root-cause classification principle (included in agent prompts)
ROOT_CAUSE_CLASSIFICATION = """\
Classify by ROOT CAUSE (the minimal code fix), not the observable effect:
- Missing access check causes price change → access-control (fix = add require)
- Missing input validation enables arbitrary call → input-validation (fix = validate input)
- Correct formula but manipulated price input → price-manipulation (fix = use TWAP/oracle)

Distinguishing access-control vs input-validation:
- access-control: fix compares msg.sender against a CONTRACT-STORED variable (owner, admin, role, allowance, whitelisted pool address computed via CREATE2). The question is "is this caller authorized?"
- input-validation: fix validates a USER-SUPPLIED PARAMETER (e.g. require(from == msg.sender) where 'from' is a function argument). The question is "is this input valid?"
Example: burn(address from, uint256 amount) without require(from == msg.sender) → input-validation (the 'from' parameter is user-supplied and not validated).
Example: setAdmin(address) without require(msg.sender == owner) → access-control (checking caller against stored owner).
Example: uniswapV3SwapCallback without verifying msg.sender is a legitimate pool → access-control (checking caller against system-derived address).
"""


DETECT_TYPE_ALIASES = {
    # accounting-error
    "accounting-error": "accounting-error",
    "accounting error": "accounting-error",
    "precision-loss": "accounting-error",
    "precision loss": "accounting-error",
    "integer-overflow": "accounting-error",
    "integer overflow": "accounting-error",
    "overflow": "accounting-error",
    "underflow": "accounting-error",
    "integer-underflow": "accounting-error",
    "rounding-error": "accounting-error",
    "rounding error": "accounting-error",
    "incorrect-calculation": "accounting-error",
    "incorrect calculation": "accounting-error",
    "business-logic": "accounting-error",
    "business logic": "accounting-error",
    "business-logic-flaw": "accounting-error",
    "logic-error": "accounting-error",
    "logic error": "accounting-error",
    "logic-flaw": "accounting-error",
    "inflation-attack": "accounting-error",
    "share-inflation": "accounting-error",
    "reflection-token": "accounting-error",
    "rebasing-logic-issue": "accounting-error",
    "token-incompatible": "accounting-error",
    "fee-logic": "accounting-error",
    "slippage": "accounting-error",
    "lack-slippage-protection": "accounting-error",
    "storage-collision": "accounting-error",
    # price-manipulation
    "price-manipulation": "price-manipulation",
    "price manipulation": "price-manipulation",
    "oracle-manipulation": "price-manipulation",
    "oracle manipulation": "price-manipulation",
    "flash-loan": "price-manipulation",
    "flash loan": "price-manipulation",
    "flashloan": "price-manipulation",
    "sandwich-attack": "price-manipulation",
    "sandwich attack": "price-manipulation",
    # access-control
    "access-control": "access-control",
    "access control": "access-control",
    "authorization": "access-control",
    "auth": "access-control",
    "rug-pull": "access-control",
    "rug pull": "access-control",
    "backdoor": "access-control",
    "phishing": "access-control",
    # reentrancy
    "reentrancy": "reentrancy",
    "re-entrancy": "reentrancy",
    # input-validation
    "unsafe-external-call": "input-validation",
    "unsafe external call": "input-validation",
    "unchecked-call": "input-validation",
    "unchecked call": "input-validation",
    "unchecked-external-call": "input-validation",
    "unchecked external call": "input-validation",
    "arbitrary-external-call": "input-validation",
    "arbitrary external call": "input-validation",
    "input-validation": "input-validation",
    "input validation": "input-validation",
    "insufficient-validation": "input-validation",
    "missing-validation": "input-validation",
    "weak-randomness": "input-validation",
    "weak-rng": "input-validation",
    "signature-replay": "input-validation",
    "signature-malleability": "input-validation",
    "misconfiguration": "input-validation",
    # legacy catch-all
    "other": "accounting-error",
}

# Canonical type descriptions shared by all agents (fill, detect, exploit, fix).
# Each entry defines the type, its boundary, and what distinguishes it from neighbors.
# The sub-patterns listed under each type are representative examples, NOT an
# exhaustive list.  Any vulnerability whose root cause matches the type's
# definition belongs to that type, even if it is not explicitly listed below.
#
# CLASSIFICATION PRINCIPLE: always classify by ROOT CAUSE, not by the observable effect.
# Examples:
#   - A missing access check on burn() lets anyone burn LP tokens → price changes.
#     Root cause = access-control (not price-manipulation), because the fix is adding a require().
#   - A missing input validation on a call target lets attacker redirect a delegatecall.
#     Root cause = input-validation (not unsafe-external-call), because the fix is validating the input.
#   - A function uses spot price from AMM reserves, attacker flash-loans to skew reserves.
#     Root cause = price-manipulation (not accounting-error), because the formula is correct but the input price is manipulated.
# Ask: "What is the minimal code change that fixes this?" — that tells you the root cause type.
VULNERABILITY_TYPE_DESCRIPTIONS = {
    "accounting-error": (
        "The contract's internal logic produces an incorrect result — a wrong amount, state transition, "
        "or control flow — allowing an attacker to extract value.\n"
        "\n"
        "Sub-patterns (representative, not exhaustive):\n"
        "- Precision loss: integer division truncation or rounding errors (e.g. amount * rate / 1e18 loses low bits).\n"
        "- Integer overflow / underflow: arithmetic exceeds uint256 bounds (pre-SafeMath or unchecked blocks).\n"
        "- Share calculation error: deposit/withdraw/mint/redeem computes the wrong share-to-asset ratio.\n"
        "- First-depositor inflation: attacker donates to manipulate share price so later depositors lose to rounding.\n"
        "- Transfer fee / tax bug: _transfer hook deducts fee/burn/tax incorrectly.\n"
        "- Reflection / rebasing token incompatibility: external token balance changes automatically; contract ignores this.\n"
        "- Reward / dividend miscalculation: accumulator or claim logic distributes wrong amounts.\n"
        "- Missing slippage protection: swap or withdrawal has no minAmountOut check.\n"
        "- Storage collision: proxy upgrade misaligns storage layout.\n"
        "- Business logic flaw: state machine transitions, order of operations, or conditional branching is incorrect.\n"
        "\n"
        "Boundary: the root cause is a bug in the contract's own logic (numeric or otherwise) that produces a wrong outcome. "
        "If the attacker must first manipulate an external price to make the result wrong, that is price-manipulation, not accounting-error. "
        "If the function is correct but callable by the wrong person, that is access-control."
    ),
    "price-manipulation": (
        "The attacker manipulates an on-chain price, exchange rate, or share price, "
        "then profits from a victim contract that reads the manipulated value.\n"
        "\n"
        "Sub-patterns (representative, not exhaustive):\n"
        "- AMM pool manipulation: large swap skews pair reserves so getAmountOut or reserve-ratio consumers get a wrong price.\n"
        "- Spot price reliance: contract uses instantaneous price (getReserves, balanceOf(pair), slot0) instead of TWAP, "
        "making it trivially manipulable within a single transaction.\n"
        "- Oracle manipulation: attacker corrupts a Chainlink / TWAP / custom oracle return value.\n"
        "- Flash-loan price manipulation: flash-borrowed capital amplifies the pool distortion.\n"
        "- Sandwich attack: attacker front-runs and back-runs a victim swap to extract value.\n"
        "- Share-price manipulation: donation to a vault changes totalAssets, warping the share price for a dependent contract.\n"
        "\n"
        "Boundary: the attack has a two-step structure — first manipulate a price, then exploit a contract that trusts that price. "
        "A contract that reads spot/instantaneous price without TWAP or other manipulation resistance is price-manipulation "
        "even if the formula itself is arithmetically correct. "
        "If the contract's own formula is wrong regardless of any external price change, that is accounting-error."
    ),
    "access-control": (
        "The contract does not properly restrict who can call a privileged operation, "
        "allowing an unauthorized caller to execute it.\n"
        "\n"
        "Sub-patterns (representative, not exhaustive):\n"
        "- Missing modifier: sensitive function (mint, pause, upgrade, setFee) lacks onlyOwner or role check.\n"
        "- Bypassable check: access check exists but is flawed (e.g. uses tx.origin instead of msg.sender).\n"
        "- Unprotected initializer: initialize() can be called by anyone.\n"
        "- Backdoor / rug-pull: owner retains unreasonable privilege (e.g. can drain the pool).\n"
        "- Phishing / social engineering: attacker obtains a valid signature or key through off-chain deception.\n"
        "\n"
        "Boundary: the root cause is a missing or incorrect identity / role check on msg.sender. "
        "If the right caller passes bad parameters, that is input-validation. "
        "If anyone can call the function and the bug is in the calculation, that is accounting-error."
    ),
    "reentrancy": (
        "The contract makes an external call and fails to guard against re-entry, "
        "allowing the callee to call back into the contract while state is inconsistent.\n"
        "\n"
        "Sub-patterns (representative, not exhaustive):\n"
        "- Classic reentrancy: state is updated after an external call; the callee re-enters and exploits stale state.\n"
        "- Cross-contract reentrancy: the callback re-enters a different contract in the same protocol.\n"
        "- Read-only reentrancy: a view function returns intermediate state during the callback.\n"
        "\n"
        "Boundary: the root cause is that state updates happen after an external call, and the callee exploits the stale state. "
        "If the called address is user-supplied and the contract fails to validate it, that is input-validation. "
        "If the called address is trusted and fixed but the parameters are wrong, that is accounting-error."
    ),
    "input-validation": (
        "The contract does not sufficiently validate incoming parameters, data, or external messages, "
        "allowing an attacker to supply malicious or unexpected values that trigger unintended behavior.\n"
        "\n"
        "Sub-patterns (representative, not exhaustive):\n"
        "- Missing parameter check: amount, address, or path argument lacks bounds or sanity check.\n"
        "- Arbitrary external call: contract accepts a user-supplied target address or calldata without validation "
        "and executes .call() / .delegatecall() / approve() on it, letting the attacker redirect funds or invoke arbitrary contracts.\n"
        "- Signature replay: signature can be reused across transactions or chains.\n"
        "- Signature malleability: ECDSA s-value is not canonicalized, allowing a second valid signature.\n"
        "- Weak randomness: contract uses block.timestamp, blockhash, or other predictable on-chain data as entropy.\n"
        "- Misconfiguration: deployment parameters are set incorrectly (e.g. fee = 0, threshold too low).\n"
        "- Cross-chain message validation: bridge contract does not properly verify the source or content of a cross-chain message.\n"
        "\n"
        "Boundary: the root cause is that the contract fails to check what was passed in (calldata, message, address, config). "
        "If the issue is who called the function, that is access-control. "
        "If the input is valid but the contract's own formula is wrong, that is accounting-error. "
        "If the target address is hardcoded/fixed and the issue is state update ordering after a call, that is reentrancy."
    ),
}


def normalize_detect_type_label(value: object) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    if not raw:
        return ""
    if raw in DETECT_TYPE_ALIASES:
        return DETECT_TYPE_ALIASES[raw]
    for alias, normalized in DETECT_TYPE_ALIASES.items():
        alias_normalized = alias.replace("_", "-")
        if raw == alias_normalized or alias_normalized in raw:
            return normalized
    return raw


__all__ = [
    "DETECT_VULNERABILITY_TYPES",
    "DETECT_TYPE_ALIASES",
    "VULNERABILITY_TYPE_DESCRIPTIONS",
    "normalize_detect_type_label",
]
