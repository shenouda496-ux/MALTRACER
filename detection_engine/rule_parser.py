import re

def load_rules(path):
    rules = []
    
    current_rule = None

    with open(path, "r") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith("IF "):
                if current_rule:
                    rules.append(current_rule)
                
                # Loose keyword matching setup
                condition = line[3:].strip().lower()
                current_rule = {
                    "keywords": [condition],
                    "score": 0
                }
            elif line.startswith("AND ") and current_rule:
                condition = line[4:].strip().lower()
                current_rule["keywords"].append(condition)
            elif line.startswith("THEN score +") and current_rule:
                try:
                    score = int(line.replace("THEN score +", "").strip())
                    current_rule["score"] = score
                except ValueError:
                    pass

    if current_rule:
        rules.append(current_rule)

    return rules