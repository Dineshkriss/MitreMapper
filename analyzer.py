import json
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from sentence_transformers import SentenceTransformer
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer


# Cell 2: Dataclass Definitions
@dataclass
class TTMapping:
    """Structured mapping output"""
    tactic: str
    technique: str
    sub_technique: Optional[str]
    procedure: str
    threat_actors: List[str]
    text: str  # Original text snippet from report
    confidence: float
    
    def to_dict(self):
        return asdict(self)

@dataclass
class ActionPlan:
    """Remediation action plan"""
    for_organizations: List[Dict[str, str]]  # {mitigation, attack_id, description}
    for_individuals: List[str]  # Immediate checklist items

@dataclass
class ThreatAnalysis:
    """Complete analysis output"""
    mappings: List[TTMapping]
    action_plan: ActionPlan
    summary: str  # Description of what happened and how
    
    def to_dict(self):
        return {
            "mappings": [m.to_dict() for m in self.mappings],
            "action_plan": {
                "for_organizations": self.action_plan.for_organizations,
                "for_individuals": self.action_plan.for_individuals
            },
            "summary": self.summary
        }


# Cell 3: MITREKnowledgeBase Class
class MITREKnowledgeBase:
    """Manages MITRE ATT&CK matrices and mappings"""
    
    def __init__(
        self,
        enterprise_path: str = "attack-matrices/enterprise-attack.json",
        ics_path: str = "attack-matrices/ics-attack.json",
        mobile_path: str = "attack-matrices/mobile-attack.json",
        mappings_path: str = "mitre_mappings.json"
    ):
        self.enterprise = self._load_matrix(enterprise_path)
        self.ics = self._load_matrix(ics_path)
        self.mobile = self._load_matrix(mobile_path)
        self.historical_mappings = self._load_mappings(mappings_path)
        
        # Build lookup tables
        self.technique_lookup = self._build_technique_lookup()
        self.tactic_lookup = self._build_tactic_lookup()
        self.mitigation_lookup = self._build_mitigation_lookup()
        
    def _load_matrix(self, path: str) -> Dict:
        """Load MITRE ATT&CK matrix"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: {path} not found")
            return {"objects": []}
    
    def _load_mappings(self, path: str) -> List[Dict]:
        """Load historical mappings for few-shot examples"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: {path} not found")
            return []
    
    def _build_technique_lookup(self) -> Dict[str, Dict]:
        """Build technique ID -> full details lookup"""
        lookup = {}
        for matrix in [self.enterprise, self.ics, self.mobile]:
            for obj in matrix.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    tech_id = None
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id")
                            break
                    
                    if tech_id:
                        lookup[tech_id] = {
                            "id": tech_id,
                            "name": obj.get("name"),
                            "description": obj.get("description", ""),
                            "platforms": obj.get("x_mitre_platforms", []),
                            "tactics": [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])],
                            "is_subtechnique": "." in tech_id
                        }
        return lookup
    
    def _build_tactic_lookup(self) -> Dict[str, Dict]:
        """Build tactic ID -> details lookup"""
        lookup = {}
        for matrix in [self.enterprise, self.ics, self.mobile]:
            for obj in matrix.get("objects", []):
                if obj.get("type") == "x-mitre-tactic":
                    tactic_id = None
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tactic_id = ref.get("external_id")
                            break
                    
                    if tactic_id:
                        lookup[tactic_id] = {
                            "id": tactic_id,
                            "name": obj.get("name"),
                            "description": obj.get("description", "")
                        }
        return lookup
    
    def _build_mitigation_lookup(self) -> Dict[str, List[Dict]]:
        """Build technique ID -> mitigations lookup"""
        mitigations = {}
        target_to_ext_id = {}
        
        for matrix in [self.enterprise, self.ics, self.mobile]:
            for obj in matrix.get("objects", []):
                # Cache mitigations
                if obj.get("type") == "course-of-action":
                    mit_id = None
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            mit_id = ref.get("external_id")
                            break
                    
                    if mit_id:
                        mitigations[obj["id"]] = {
                            "id": mit_id,
                            "name": obj.get("name"),
                            "description": obj.get("description", "")
                        }
                
                # Cache technique patterns for O(1) mitigation relationship mapping
                elif obj.get("type") == "attack-pattern":
                    tech_ext_id = None
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tech_ext_id = ref.get("external_id")
                            break
                    if tech_ext_id:
                        target_to_ext_id[obj["id"]] = tech_ext_id
                        
        # Build technique -> mitigations mapping using fast lookup
        lookup = {}
        for matrix in [self.enterprise, self.ics, self.mobile]:
            for obj in matrix.get("objects", []):
                if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
                    target_id = obj.get("target_ref")
                    source_id = obj.get("source_ref")
                    
                    if source_id in mitigations and target_id in target_to_ext_id:
                        tech_ext_id = target_to_ext_id[target_id]
                        if tech_ext_id not in lookup:
                            lookup[tech_ext_id] = []
                        lookup[tech_ext_id].append(mitigations[source_id])
        
        return lookup
    
    def get_similar_mappings(self, text: str, top_k: int = 3) -> List[Dict]:
        """Retrieve similar historical mappings for few-shot examples (Legacy)"""
        # This is being replaced by Semantic Clustering in MITREMapper
        pass

# Cell 4: MITREMapper Class
class MITREMapper:
    def __init__(
        self,
        model_name: str = "unsloth/Llama-3.2-3B-Instruct-bnb-4bit",  # Changed default
        knowledge_base: Optional[MITREKnowledgeBase] = None
    ):
        """
        Initialize MITREMapper with Llama model and MITRE knowledge base.
        
        Args:
            model_name: HuggingFace model identifier
            knowledge_base: Pre-loaded MITRE knowledge base
            use_4bit: Use 4-bit quantization to fit in 6GB VRAM
        """
        self.knowledge_base = knowledge_base or MITREKnowledgeBase()
        
        quantized_model_name = "unsloth/Llama-3.2-3B-Instruct-bnb-4bit"

        print(f"Loading pre-quantized model: {quantized_model_name}...")
        self.tokenizer = AutoTokenizer.from_pretrained(quantized_model_name)

        self.model = AutoModelForCausalLM.from_pretrained(
            quantized_model_name,
            device_map="auto",
            low_cpu_mem_usage=True,
            trust_remote_code=True  # Required for some quantized models
        )

        # Load sentence transformer for semantic similarity (lighter model)
        print("Loading sentence transformer for embeddings...")
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Create technique embeddings for semantic search and hybrid TF-IDF search
        self._create_technique_embeddings()
        
        # Create historical mapping embeddings for few-shot learning
        self._create_mapping_embeddings()
    
    def _create_technique_embeddings(self):
        """Create dense embeddings and TF-IDF vectors for Hybrid Search"""
        print("Creating dense and sparse technique embeddings...")
        self.technique_texts = []
        self.technique_ids = []
        
        for tech_id, tech_data in self.knowledge_base.technique_lookup.items():
            text = f"{tech_data['name']}: {tech_data['description'][:200]}"
            self.technique_texts.append(text)
            self.technique_ids.append(tech_id)
        
        # 1. Dense Embeddings
        self.technique_embeddings = self.embedder.encode(
            self.technique_texts,
            show_progress_bar=True
        )
        
        # 2. Sparse Vectors (Exact Match / TF-IDF)
        self.tfidf_vectorizer = TfidfVectorizer(stop_words='english')
        self.technique_tfidf = self.tfidf_vectorizer.fit_transform(self.technique_texts)

    def _create_mapping_embeddings(self):
        """Create dense embeddings for historical mappings for Few-Shot Selection"""
        print("Creating historical mapping embeddings...")
        self.mapping_texts = [m.get("text", "") for m in self.knowledge_base.historical_mappings]
        
        if self.mapping_texts:
            self.mapping_embeddings = self.embedder.encode(
                self.mapping_texts, 
                show_progress_bar=False
            )
        else:
            self.mapping_embeddings = np.array([])
    
    def _find_relevant_techniques(self, text: str, top_k: int = 10) -> List[Tuple[str, float]]:
        """Find most relevant techniques using Hybrid Search (Dense + Sparse)"""
        # 1. Semantic Search (Dense)
        dense_query = self.embedder.encode([text])
        dense_similarities = cosine_similarity(dense_query, self.technique_embeddings)[0]
        
        # 2. Exact Match Search (Sparse)
        sparse_query = self.tfidf_vectorizer.transform([text])
        sparse_similarities = cosine_similarity(sparse_query, self.technique_tfidf)[0]
        
        # 3. Hybrid Score = 70% Semantic + 30% Keyword Matching
        hybrid_scores = (dense_similarities * 0.7) + (sparse_similarities * 0.3)
        
        top_indices = np.argsort(hybrid_scores)[-top_k:][::-1]
        return [(self.technique_ids[i], float(hybrid_scores[i])) for i in top_indices]

    def _find_similar_mappings(self, text: str, top_k: int = 3) -> List[Dict]:
        """Find best few-shot examples using semantic search rather than word overlap"""
        if not self.knowledge_base.historical_mappings or len(self.mapping_texts) == 0:
            return []
            
        query_embedding = self.embedder.encode([text])
        similarities = cosine_similarity(query_embedding, self.mapping_embeddings)[0]
        
        top_indices = np.argsort(similarities)[-top_k:][::-1]
        
        # Filter purely unrelated mappings (threshold > 0.15)
        results = [self.knowledge_base.historical_mappings[i] for i in top_indices if similarities[i] > 0.15]
        return results
    
    def _generate_with_llm(self, prompt: str, max_tokens: int = 2048) -> str:
        """Generate response from Llama model"""
        messages = [
            {"role": "system", "content": "You are a cybersecurity expert specializing in MITRE ATT&CK framework mapping and threat analysis."},
            {"role": "user", "content": prompt}
        ]
        
        input_text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        
        inputs = self.tokenizer(input_text, return_tensors="pt").to(self.model.device)
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                temperature=0.7,
                top_p=0.9,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        response = self.tokenizer.decode(outputs[0][inputs['input_ids'].shape[1]:], skip_special_tokens=True)
        return response.strip()
    
    def _extract_threat_indicators(self, report: str) -> Dict[str, Any]:
        """Extract key indicators from threat report"""
        prompt = f"""Analyze this threat intelligence report and extract key information:

REPORT:
{report}

Extract and provide in JSON format:
1. threat_actors: List of threat actor names/groups mentioned (if any)
2. key_behaviors: List of specific malicious behaviors described
3. indicators: Technical indicators (IPs, domains, file hashes, commands, etc.)
4. platforms: Affected platforms (Windows, Linux, macOS, etc.)

Respond ONLY with valid JSON."""

        response = self._generate_with_llm(prompt, max_tokens=1024)
        
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
        
        # Fallback to basic extraction
        return {
            "threat_actors": [],
            "key_behaviors": [report[:200]],
            "indicators": [],
            "platforms": []
        }
    
    def _map_to_ttps(self, report: str, extracted_info: Dict) -> List[TTMapping]:
        """Map report to MITRE ATT&CK TTPs using hierarchical classification"""
        
        # Get similar historical mappings using Dense Embeddings (Upgraded)
        similar_mappings = self._find_similar_mappings(report, top_k=3)
        
        # Get relevant techniques using semantic search
        relevant_techniques = self._find_relevant_techniques(report, top_k=15)
        
        # Build context with technique details
        technique_context = "\n\n".join([
            f"ID: {tech_id}\nName: {self.knowledge_base.technique_lookup[tech_id]['name']}\n"
            f"Description: {self.knowledge_base.technique_lookup[tech_id]['description'][:150]}...\n"
            f"Tactics: {', '.join(self.knowledge_base.technique_lookup[tech_id]['tactics'])}"
            for tech_id, _ in relevant_techniques[:10]
        ])
        
        # Build few-shot examples
        few_shot_examples = ""
        if similar_mappings:
            few_shot_examples = "Here are examples of similar threat reports mapped to MITRE ATT&CK:\n\n"
            for i, mapping in enumerate(similar_mappings[:2], 1):
                few_shot_examples += f"Example {i}:\n"
                few_shot_examples += f"Text: {mapping.get('text', '')}\n"
                few_shot_examples += f"Technique: {mapping['technique']['id']} - {mapping['technique']['name']}\n"
                if mapping.get('sub-technique'):
                    few_shot_examples += f"Sub-technique: {mapping['sub-technique']['id']} - {mapping['sub-technique']['name']}\n"
                few_shot_examples += f"Tactic: {mapping['tactic']['name']}\n\n"
        
        prompt = f"""{few_shot_examples}

RELEVANT MITRE ATT&CK TECHNIQUES:
{technique_context}

THREAT REPORT TO ANALYZE:
{report}

EXTRACTED INFORMATION:
- Threat Actors: {', '.join(extracted_info.get('threat_actors', [])) or 'Unknown'}
- Key Behaviors: {'; '.join(extracted_info.get('key_behaviors', []))}
- Platforms: {', '.join(extracted_info.get('platforms', [])) or 'Unknown'}

TASK:
Map this threat report to MITRE ATT&CK framework. For EACH distinct malicious behavior or technique mentioned:

1. Identify the specific text snippet describing the behavior
2. Map to the most appropriate Technique ID from the relevant techniques above
3. If applicable, identify the Sub-technique ID
4. Identify the Tactic (e.g., Initial Access, Persistence, etc.)
5. Describe the specific procedure used
6. Assign a confidence score (0.0-1.0)

Respond with a JSON array of mappings in this EXACT format:
[
  {{
    "text": "exact quote from report",
    "technique_id": "T1059",
    "sub_technique_id": "T1059.001",
    "tactic": "Execution",
    "procedure": "description of how technique was used",
    "confidence": 0.95
  }}
]

Respond ONLY with the JSON array, no other text."""

        response = self._generate_with_llm(prompt, max_tokens=2048)
        
        # Parse response
        try:
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                mappings_data = json.loads(json_match.group())
                
                # Convert to TTMapping objects
                tt_mappings = []
                for mapping in mappings_data:
                    tech_id = mapping.get('technique_id', '')
                    sub_tech_id = mapping.get('sub_technique_id')
                    
                    # Get technique details
                    tech_info = self.knowledge_base.technique_lookup.get(tech_id, {})
                    tech_name = f"{tech_id} - {tech_info.get('name', 'Unknown')}"
                    
                    sub_tech_name = None
                    if sub_tech_id:
                        sub_tech_info = self.knowledge_base.technique_lookup.get(sub_tech_id, {})
                        sub_tech_name = f"{sub_tech_id} - {sub_tech_info.get('name', 'Unknown')}"
                    
                    tt_mappings.append(TTMapping(
                        tactic=mapping.get('tactic', 'Unknown'),
                        technique=tech_name,
                        sub_technique=sub_tech_name,
                        procedure=mapping.get('procedure', ''),
                        threat_actors=extracted_info.get('threat_actors', []),
                        text=mapping.get('text', ''),
                        confidence=mapping.get('confidence', 0.5)
                    ))
                
                return tt_mappings
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error parsing LLM response: {e}")
        
        # Fallback: create basic mapping from top relevant technique
        if relevant_techniques:
            top_tech_id, confidence = relevant_techniques[0]
            tech_info = self.knowledge_base.technique_lookup[top_tech_id]
            
            return [TTMapping(
                tactic=tech_info['tactics'][0] if tech_info['tactics'] else 'Unknown',
                technique=f"{top_tech_id} - {tech_info['name']}",
                sub_technique=None,
                procedure="Automated mapping based on semantic similarity",
                threat_actors=extracted_info.get('threat_actors', []),
                text=report[:200],
                confidence=confidence
            )]
        
        return []
    
    def _generate_action_plan(self, mappings: List[TTMapping], report: str) -> ActionPlan:
        """Generate remediation action plan for organizations and individuals"""
        
        # Get mitigations for identified techniques
        org_mitigations = []
        seen_mitigations = set()
        
        for mapping in mappings:
            # Extract technique ID
            tech_id = mapping.technique.split(' - ')[0] if ' - ' in mapping.technique else mapping.technique
            
            mitigations = self.knowledge_base.mitigation_lookup.get(tech_id, [])
            for mitigation in mitigations:
                mit_key = mitigation['id']
                if mit_key not in seen_mitigations:
                    seen_mitigations.add(mit_key)
                    org_mitigations.append({
                        "mitigation": mitigation['name'],
                        "attack_id": mitigation['id'],
                        "description": mitigation['description'][:200] + "..."
                    })
        
        # Generate individual action checklist
        techniques_summary = "\n".join([
            f"- {m.technique}: {m.procedure}" for m in mappings[:5]
        ])
        
        prompt = f"""Based on this threat analysis, create an immediate action checklist for individuals who have been hacked.

IDENTIFIED TECHNIQUES:
{techniques_summary}

THREAT REPORT CONTEXT:
{report[:500]}

Create a prioritized checklist of 5-10 immediate actions an individual should take. Focus on:
1. Immediate containment (disconnect, change passwords, etc.)
2. Evidence preservation
3. System cleanup
4. Recovery steps
5. Prevention measures

Respond with a JSON array of action items in this format:
["Action 1", "Action 2", ...]

Keep actions clear, specific, and actionable. Respond ONLY with the JSON array."""

        response = self._generate_with_llm(prompt, max_tokens=1024)
        
        # Parse individual actions
        individual_actions = []
        try:
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                individual_actions = json.loads(json_match.group())
        except json.JSONDecodeError:
            # Fallback actions
            individual_actions = [
                "Immediately disconnect the affected system from the network",
                "Change all passwords from a clean device",
                "Enable multi-factor authentication on all accounts",
                "Run a full system antivirus scan",
                "Review recent account activity for unauthorized access",
                "Back up important files to secure offline storage",
                "Contact your IT department or security team",
                "Monitor financial accounts for suspicious activity"
            ]
        
        return ActionPlan(
            for_organizations=org_mitigations,
            for_individuals=individual_actions
        )
    
    def _generate_summary(self, report: str, mappings: List[TTMapping]) -> str:
        """Generate human-readable summary of what happened and how"""
        
        techniques_context = "\n".join([
            f"- {m.tactic} → {m.technique}: {m.procedure}"
            for m in mappings[:5]
        ])
        
        prompt = f"""Provide a clear, concise summary of this cybersecurity incident for a non-technical audience.

THREAT REPORT:
{report}

IDENTIFIED TECHNIQUES:
{techniques_context}

Write a 2-3 paragraph summary that explains:
1. WHAT happened (what type of attack)
2. HOW it happened (attack methodology)
3. WHY it matters (potential impact)

Use clear language that a non-expert can understand. Avoid excessive jargon."""

        summary = self._generate_with_llm(prompt, max_tokens=512)
        return summary
    
    def analyze(self, report: str) -> ThreatAnalysis:
        """
        Complete analysis pipeline: map report to TTPs and generate action plan.
        
        Args:
            report: Threat intelligence report text
            
        Returns:
            ThreatAnalysis object with mappings, action plan, and summary
        """
        print("\n=== Starting Threat Analysis ===\n")
        
        # Step 1: Extract threat indicators
        print("Step 1: Extracting threat indicators...")
        extracted_info = self._extract_threat_indicators(report)
        print(f"Found: {len(extracted_info.get('threat_actors', []))} threat actors, "
              f"{len(extracted_info.get('key_behaviors', []))} behaviors")
        
        # Step 2: Map to TTPs
        print("\nStep 2: Mapping to MITRE ATT&CK TTPs...")
        mappings = self._map_to_ttps(report, extracted_info)
        print(f"Identified {len(mappings)} TTP mappings")
        
        # Step 3: Generate action plan
        print("\nStep 3: Generating remediation action plan...")
        action_plan = self._generate_action_plan(mappings, report)
        print(f"Created action plan with {len(action_plan.for_organizations)} org mitigations "
              f"and {len(action_plan.for_individuals)} individual actions")
        
        # Step 4: Generate summary
        print("\nStep 4: Generating threat summary...")
        summary = self._generate_summary(report, mappings)
        
        print("\n=== Analysis Complete ===\n")
        
        return ThreatAnalysis(
            mappings=mappings,
            action_plan=action_plan,
            summary=summary
        )


# Cell 5: Main Execution Block
if __name__ == "__main__":
    # Initialize
    print("Initializing MITREMapper...")
    kb = MITREKnowledgeBase()
    mapper = MITREMapper(knowledge_base=kb)
    
    # Example threat report
    example_report = """
    i have ransomware
    """
    
    # Analyze
    analysis = mapper.analyze(example_report)
    
    # Output results
    print("\n" + "="*80)
    print("THREAT ANALYSIS RESULTS")
    print("="*80)
    
    print("\n--- SUMMARY ---")
    print(analysis.summary)
    
    print("\n--- TTP MAPPINGS ---")
    for i, mapping in enumerate(analysis.mappings, 1):
        print(f"\n{i}. Tactic: {mapping.tactic}")
        print(f"   Technique: {mapping.technique}")
        if mapping.sub_technique:
            print(f"   Sub-technique: {mapping.sub_technique}")
        print(f"   Procedure: {mapping.procedure}")
        print(f"   Evidence: \"{mapping.text}\"")
        print(f"   Confidence: {mapping.confidence:.2f}")
        if mapping.threat_actors:
            print(f"   Threat Actors: {', '.join(mapping.threat_actors)}")
    
    print("\n--- ACTION PLAN: FOR ORGANIZATIONS ---")
    for i, mitigation in enumerate(analysis.action_plan.for_organizations, 1):
        print(f"\n{i}. [{mitigation['attack_id']}] {mitigation['mitigation']}")
        print(f"   {mitigation['description']}")
    
    print("\n--- ACTION PLAN: FOR INDIVIDUALS ---")
    for i, action in enumerate(analysis.action_plan.for_individuals, 1):
        print(f"{i}. {action}")
    
    # Save results
    output_path = "threat_analysis_results.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(analysis.to_dict(), f, indent=2)
    print(f"\n\nResults saved to {output_path}")