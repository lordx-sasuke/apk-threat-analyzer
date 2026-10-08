class ScoringEngine:
    WEIGHTS = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 7,
        "LOW": 2
    }

    @staticmethod
    def calculate(findings):
        raw_penalty = sum(ScoringEngine.WEIGHTS.get(f["severity"], 1) for f in findings)
        final_score = max(0, 100 - raw_penalty)
        
        if final_score >= 85:
            posture = "SECURE (Low Risk Exposure)"
        elif final_score >= 60:
            posture = "MODERATE (Remediation Needed)"
        elif final_score >= 40:
            posture = "ELEVATED (High Risk Exposure)"
        else:
            posture = "CRITICAL (Severe Exposure Detected)"
            
        return final_score, posture
