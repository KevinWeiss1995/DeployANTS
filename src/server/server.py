from flask import Flask, request, jsonify
from gpt4all import GPT4All
from concurrent.futures import ThreadPoolExecutor
import queue
import logging
from src.config import Config
from src.model.model_loader import ModelLoader
from src.explanations.pattern_registry import PatternRegistry
import os
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
config = Config()
model_loader = ModelLoader(config)
request_queue = queue.Queue()
registry = PatternRegistry()

# Load all pattern files from patterns directory
patterns_dir = Path(__file__).parent.parent / "explanations" / "patterns"
pattern_count = 0
for pattern_file in patterns_dir.glob("*.yaml"):
    try:
        registry.load_patterns(str(pattern_file))
        pattern_count += 1
        logger.info(f"Loaded attack pattern from {pattern_file.name}")
    except Exception as e:
        logger.error(f"Failed to load pattern from {pattern_file}: {str(e)}")

logger.info(f"Successfully loaded {pattern_count} attack patterns")
logger.info(f"Available patterns: {list(registry.patterns.keys())}")

def construct_prompt(features, prediction, feature_names, question=None):
    # Convert features list to dict
    feature_dict = dict(zip(feature_names, features))
    
    # Find matching patterns
    matches = registry.match_traffic(feature_dict)
    
    # Format descriptions with actual values
    descriptions = []
    for pattern in matches:
        try:
            desc = pattern.description.format(**feature_dict)
            descriptions.append(f"{pattern.name} ({pattern.severity}): {desc}")
        except KeyError as e:
            logger.warning(f"Failed to format pattern {pattern.name}: {e}")
            continue
        
    if not question:
        return f"""System: You are a SOC analyst assistant. Analyze this traffic pattern.

Traffic Analysis:
- Classification: {'Malicious' if prediction > 0.5 else 'Benign'} (confidence: {prediction:.1%})
- Detected Patterns:
{chr(10).join(f'  * {d}' for d in descriptions)}

Explain the significance and recommend actions based on the severity."""
    else:
        base_prompt = f"""System: You are a SOC analyst assistant. Provide specific, actionable advice based on the previous traffic analysis.

        Context:
        {chr(10).join(f"- {insight}" for insight in descriptions)}

        User: {question}

        Assistant: """
        return base_prompt

class ExplanationServer:
    def __init__(self):
        self.model = GPT4All(config.llm_model)
        self.executor = ThreadPoolExecutor(max_workers=config.llm_max_workers)
        self.network_model = model_loader.load_model()
        self._load_model()
    
    def _load_model(self):
        self.model.generate("test", max_tokens=1)

server = ExplanationServer()

@app.route('/explain', methods=['POST'])
def explain_traffic():
    data = request.json
    prompt = construct_prompt(
        data['features'],
        data['prediction'],
        data['feature_names'],
        data.get('question')
    )
    
    explanation = server.model.generate(
        prompt,
        max_tokens=150,
        temp=0.7,
        top_k=40,
        top_p=0.4,
        repeat_penalty=1.18
    )
    
    return jsonify({"explanation": explanation})

if __name__ == '__main__':
    app.run(host=config.server_host, port=config.server_port) 