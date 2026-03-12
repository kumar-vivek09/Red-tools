class ExposureClassifier:

    def classify(self, risk_score):

        if risk_score < 2:
            return "Low"

        elif risk_score < 5:
            return "Moderate"

        elif risk_score < 8:
            return "High"

        else:
            return "Critical"