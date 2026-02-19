def decide_decoy_action(intent_label):
    mapping = {
        "Safe": "monitor",
        "Recon": "deploy_low_interaction",
        "Downloader": "deploy_medium_interaction",
        "Exploit": "deploy_high_interaction",
        "Destructive": "isolate_and_deploy_high_interaction",
        "ADVANCED_APT": "contain_and_shadow",
    }
    return mapping.get(intent_label, "monitor")
