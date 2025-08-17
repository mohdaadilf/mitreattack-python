from mitreattack.stix20 import MitreAttackData

# Load ATT&CK JSON into memory
ATTACK_JSON = r"<path>"
mitre_attack_data = MitreAttackData(ATTACK_JSON)

# --------- Build fast lookup dict ---------
technique_to_tactics = {}

def add_to_lookup(technique):
    """Helper: extract external_id + tactics and store in dictionary"""
    external_id = None
    for ref in technique.external_references:
        if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id")
            break

    if external_id:
        tactics = mitre_attack_data.get_tactics_by_technique(technique.id)
        technique_to_tactics[external_id.upper()] = [t.name for t in tactics]


# Add techniques
for technique in mitre_attack_data.get_techniques():
    add_to_lookup(technique)

# Add sub-techniques
for subtechnique in mitre_attack_data.get_subtechniques():
    add_to_lookup(subtechnique)


def get_tactics_for_technique(external_id: str):
    """Fast lookup from prebuilt dictionary (works for techniques & sub-techniques)"""
    return technique_to_tactics.get(external_id, [])


if __name__ == "__main__":
    test_ids = ["T1098", "T1098.001", "T1547.001", "T1561.001"]
    for tid in test_ids:
        tactic_names = get_tactics_for_technique(tid)
        if tactic_names:
            print(f"{tid} → {', '.join(tactic_names)}")
        else:
            print(f"{tid} → No tactics found")
