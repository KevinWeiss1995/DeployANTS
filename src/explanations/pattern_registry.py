from dataclasses import dataclass
from typing import Dict, Tuple, List, Optional, Union
import yaml
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

@dataclass
class Indicator:
    feature: str
    min_value: float
    max_value: Union[float, str]
    description: str

    @classmethod
    def from_dict(cls, data: dict):
        max_val = float('inf') if data['max_value'] == 'inf' else float(data['max_value'])
        return cls(
            feature=data['feature'],
            min_value=float(data['min_value']),
            max_value=max_val,
            description=data['description']
        )

@dataclass
class AttackPattern:
    name: str
    indicators: List[Indicator]
    description: str
    severity: str
    mitigations: List[str]
    references: List[str]
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            name=data['name'],
            indicators=[Indicator.from_dict(i) for i in data['indicators']],
            description=data['description'],
            severity=data['severity'],
            mitigations=data['mitigations'],
            references=data['references']
        )

class PatternRegistry:
    def __init__(self):
        self.patterns: Dict[str, AttackPattern] = {}
        
    def load_patterns(self, path: str):
        """Load patterns from YAML or JSON file"""
        suffix = Path(path).suffix
        with open(path) as f:
            if suffix == '.yaml' or suffix == '.yml':
                patterns = yaml.safe_load(f)
            else:
                patterns = json.load(f)
                
        for pattern in patterns:
            try:
                self.add_pattern(AttackPattern.from_dict(pattern))
            except Exception as e:
                logger.error(f"Failed to load pattern: {e}")
    
    def add_pattern(self, pattern: AttackPattern):
        self.patterns[pattern.name] = pattern
        
    def match_traffic(self, features: Dict[str, float]) -> List[AttackPattern]:
        """Find all patterns that match the traffic"""
        matches = []
        for pattern in self.patterns.values():
            if self._matches_pattern(features, pattern):
                matches.append(pattern)
        return matches
                
    def _matches_pattern(self, features: Dict[str, float], pattern: AttackPattern) -> bool:
        for indicator in pattern.indicators:
            if indicator.feature not in features:
                return False
            value = float(features[indicator.feature])
            if not (indicator.min_value <= value <= indicator.max_value):
                return False
        return True 