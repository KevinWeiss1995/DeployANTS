import numpy as np
from gpt4all import GPT4All
import logging
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

class NetworkExplainer:
    def __init__(self, model_path=None):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        model_name = "orca-mini-3b-gguf2-q4_0.gguf"
        self.model = GPT4All(model_name if not model_path else model_path)
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        self.thresholds = {
            'SYN Flag Count': 100,
            'Flow Bytes/s': 10000,
            'Flow IAT Min': 0.0001,
            'RST Flag Count': 100,
            'PSH Flag Count': 1000,
            'Fwd Packets/s': 200,
        }
    
    @lru_cache(maxsize=1000)
    def _generate_response(self, prompt):
        return self.model.generate(
            prompt,
            max_tokens=150,
            temp=0.7,
            top_k=40,
            top_p=0.4,
            repeat_penalty=1.18
        )
        
    def explain_prediction(self, features, prediction, feature_names, follow_up_question=None):
        insights = []
        for feature, threshold in self.thresholds.items():
            if feature in feature_names:
                idx = feature_names.index(feature)
                value = features[idx]
                
                if feature == 'SYN Flag Count' and value > threshold:
                    insights.append(f"High SYN count: {int(value)} packets")
                elif feature == 'Flow Bytes/s' and value > threshold:
                    insights.append(f"High traffic rate: {value:.1f} bytes/s")
                elif feature == 'Flow IAT Min' and value < threshold:
                    insights.append(f"Very small packet intervals: {value:.6f}s")
                elif feature == 'RST Flag Count' and value > threshold:
                    insights.append(f"High RST count: {int(value)} packets")
                elif feature == 'Fwd Packets/s' and value > threshold:
                    insights.append(f"High packet rate: {value:.1f} packets/s")

        prompt = f"""System: You are a cybersecurity analyst expert in network traffic analysis. 
        Explain findings in clear, technical but accessible language. Be concise but thorough.

        Human: Analyze this network traffic:
        Classification: {'Malicious' if prediction > 0.5 else 'Benign'} (confidence: {prediction:.1%})
        Key observations:
        {chr(10).join(f"- {insight}" for insight in insights)}
        
        Additional context:
        - Normal SYN counts are usually under 50 per session
        - Normal traffic rates are under 5000 bytes/s
        - Normal packet intervals are above 0.001s
        
        Explain why this traffic is suspicious or normal.

        Assistant: """

        if follow_up_question and prediction > 0.5:
            prompt += f"\n\nHuman: {follow_up_question}\n\nAssistant: "

        future = self.executor.submit(self._generate_response, prompt)
        return future.result()

    def ask_followup(self, features, prediction, feature_names, question):
        if prediction <= 0.5:
            return "Traffic is benign. No follow-up analysis needed."
        return self.explain_prediction(features, prediction, feature_names, follow_up_question=question) 