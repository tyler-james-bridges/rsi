export class PublicProjectionError extends Error {
  readonly code: "INPUT_INVALID" | "DELAY_NOT_MET" | "SIGNATURE_INVALID" | "CHAIN_INVALID";

  constructor(code: PublicProjectionError["code"]) {
    super("Public projection operation could not be completed");
    this.name = "PublicProjectionError";
    this.code = code;
  }
}
