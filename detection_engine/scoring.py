class ScoringModel:

    def calculate(self, matched_rules):
        score = 0
        for rule in matched_rules:
            score += rule.get("score", 0)
        return score
