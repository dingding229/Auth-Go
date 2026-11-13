module.exports = guard => {
  guard.require("");
  return { marker: "AUTHGO_payload_PROTECTED_CORE", language: "node",
    unique: "AUTHGO_payload_NODE_CORE", features: guard.result().features };
};
