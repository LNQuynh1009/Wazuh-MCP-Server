#!/usr/bin/env python3


def hybrid_merge(playbook_result: dict, ai_result: dict):
    """Merge playbook and AI classification results using OR logic."""
    playbook_cls = playbook_result.get("classification", "FP")
    ai_cls = ai_result.get("classification", "FP")

    # OR condition: if either is TP → final TP
    final_tp = (playbook_cls == "TP") or (ai_cls == "TP")

    return {
        "final_classification": "TP" if final_tp else "FP",
        "playbook": playbook_result,
        "ai": ai_result,
        "category": ai_result.get("category") or playbook_result.get("category", "general"),
        "reason": f"Playbook: {playbook_result.get('reason')} | AI: {ai_result.get('short_reason')}",
        "recommended_action": ai_result.get("recommended_action") or playbook_result.get("reason", "Investigate")
    }
