# Entry-point classification regression

This application test catches missing public Move entry points and classifications
based on callback or modifier names instead of enforced caller restrictions.
`scenario.md` contains self-contained excerpts for static analysis; it is not a
compiler or chain-execution test.

Run the same request in fresh Codex sessions without conversation history:

1. Control: supply only `scenario.md` and ask the agent to complete its request.
2. Skill: supply `scenario.md`, `../skills/entry-point-analyzer/SKILL.md`, and its
   linked references. Ask the agent to complete the request using the skill.

Keep this rubric and prior reports out of both sessions. Disable shared-memory
retrieval for the isolated evaluation. Record the skill revision, model, prompt,
full responses, and any context contamination. Grade behavior, not exact wording:

- `Vault.deposit` is public while unpaused; `pause` is owner-restricted.
- Both unguarded `onERC721Received` functions are public.
- `uniswapV3SwapCallback` and `receiveFlashLoan` require the configured `pool`
  address. The excerpts do not establish that the supplied address is a contract;
  accept Review Required or a clearly conditional Contract-Only classification.
- Aptos `create` and non-entry `add` are included. `add` is script-reachable, and
  its signer argument permits writes only under that signer's address; it does
  not imply an administrator role.
- Sui non-entry `add` is included and is callable through a programmable
  transaction block using the shared counter.
- All three explicit read functions and generated Solidity getters are excluded.
- The inventory covers nine recurring state-changing functions, with source
  locations. Deployment initializers may be reported separately, not counted as
  recurring entry points.

A correct control is not a failing baseline. If the old skill requires rejecting
its instructions to answer correctly, record that conflict separately. Passing
this small fixture does not establish coverage of other languages or runtime
correctness.
