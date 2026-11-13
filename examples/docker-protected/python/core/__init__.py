def response(guard):
    guard.require("")
    return {"marker": "AUTHGO_payload_PROTECTED_CORE", "language": "python",
            "unique": "AUTHGO_payload_PYTHON_CORE", "features": guard.result.features}
