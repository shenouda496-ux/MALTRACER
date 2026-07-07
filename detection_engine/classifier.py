class ThreatClassifier:

    def classify(self, score):

        if score == 0:
            return "INFO"

        if score < 40:
            return "LOW"

        if score < 80:
            return "MEDIUM"

        return "HIGH"