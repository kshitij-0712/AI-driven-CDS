def explain_action(intent_label, confidence, action):
    return (
        f"Action '{action}' selected because intent '{intent_label}' was predicted "
        f"with confidence {confidence:.2f}."
    )
