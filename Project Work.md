# Introduction

- In today’s digital world, cyber threats aren’t just something that affects organizations or governments — they’re personal. 
- Every day, individuals fall victim to phishing scams, malware infections, or social engineering attacks. However, most people don’t know how or why it happened — and more importantly, what exactly the hacker did.
- To bridge this gap, we developed MITREMapper — a system that not only helps cybersecurity professionals by classifying observed behaviors and mapping them to MITRE ATT&CK TTPs, but also introduces a novel feature: personalized threat mapping for individuals.

# The Problem

- Cyber Threat Intelligence (CTI) reports are initially written (or are at least thought of) based on **observed behaviors** in **natural language** by threat analysts.
- These reports, written in natural language have to be mapped to the MITRE ATT&CK Tactics-Techniques-Procedures framework, which can be difficult and laborious to do manually.

# Our Objective

- Our primary objective is to automate the mapping of observed behaviors to the MITRE ATT&CK Tactics-Techniques-Procedures framework.
- **Novel Idea**
	- Guide an individual who has been hacked on what steps he/she should immediately take next, by using the report given by the individual based on observed behaviors.
	- Also give a broader picture to the individual to raise awareness on what has happened, how it happened (by correlating observed sequence of behaviors to MITRE ATT&CK TTPs), and how to prevent it in the future; to promote better cyber safety in the community.

# Solution
## Scope

- **Input**: Free text in *natural language*.
- **Outputs**
	- The problem is a **hierarchical multi-label classification** problem.
	- **Structured Mapping**
		- `{tactic, technique, sub-technique, procedure, threat-actors, text, confidence}`
	- **Action Plan**
		- **Organizations:** Mitigations from MITRE ATT&CK framework (with ATT&CK IDs).
		- **Individuals:** Immediate to-do checklist.
	- **Information**
		- Description of what happened and how it happened.

## Internal Schema

```
{
  "text": "The attacker used PowerShell scripts to execute commands for persistence.",
  "tactic": {
    "id": "TA0003",
    "name": "Persistence",
    "description": "The adversary is trying to maintain their foothold."
  },
  "technique": {
    "id": "T1059",
    "name": "Command and Scripting Interpreter",
    "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. Interpreters can be used interactively or to run scripts that enable follow-on actions such as persistence, execution, or discovery.",
    "platforms": [
      "Windows",
      "macOS",
      "Linux"
    ]
  },
  "sub-technique": {
    "id": "T1059.001",
    "name": "PowerShell",
    "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell provides a powerful interactive shell and scripting language that can be used to execute arbitrary commands or payloads and to configure persistence mechanisms.",
    "parent_id": "T1059",
    "platforms": [
      "Windows",
      "macOS",
      "Linux"
    ]
  }
}
```

## How it Works

### MITRE ATT&CK Threat Mapper - Implementation Notes

#### Overview

This system automatically maps observed behaviors to the MITRE ATT&CK framework using a 4-bit quantized Llama 3.2 3B model and semantic search. It analyzes security incidents, identifies tactics-techniques-procedures (TTPs), and generates actionable remediation plans.

---

### Architecture Components

#### 1. Data Structures

##### `TTMapping` (dataclass)

Represents a single TTP mapping with:

- `tactic`: Attack phase (e.g., "Initial Access", "Execution")
- `technique`: MITRE technique ID and name (e.g., "T1059 - Command and Scripting Interpreter")
- `sub_technique`: Optional sub-technique ID and name
- `procedure`: Specific implementation/behavior observed
- `threat_actors`: List of identified threat actor names
- `text`: Original evidence snippet from report
- `confidence`: Mapping confidence score (0.0-1.0)

##### `ActionPlan` (dataclass)

Remediation guidance with:

- `for_organizations`: List of MITRE mitigations with IDs and descriptions
- `for_individuals`: Immediate action checklist for victims

##### `ThreatAnalysis` (dataclass)

Complete analysis output containing:

- `mappings`: List of TTP mappings
- `action_plan`: Remediation recommendations
- `summary`: Human-readable incident description

---

#### 2. MITREKnowledgeBase Class

**Purpose**: Load and index MITRE ATT&CK matrices for fast lookup

##### Initialization

```python
MITREKnowledgeBase(
    enterprise_path="attack-matrices/enterprise-attack.json",
    ics_path="attack-matrices/ics-attack.json",
    mobile_path="attack-matrices/mobile-attack.json",
    mappings_path="mitre_mappings.json"
)
```

##### Key Methods

**`_build_technique_lookup()`**

- Creates `technique_id -> details` dictionary
- Extracts: ID, name, description, platforms, tactics, is_subtechnique flag
- Example: `"T1059.001"` maps to PowerShell technique details

**`_build_tactic_lookup()`**

- Creates `tactic_id -> details` dictionary
- Stores tactic names and descriptions

**`_build_mitigation_lookup()`**

- Creates `technique_id -> [mitigations]` dictionary
- Parses relationship objects to link techniques with mitigations
- Used for generating organizational action plans

**`get_similar_mappings(text, top_k=3)`**

- Retrieves historical mappings for few-shot learning
- Uses simple word overlap scoring (can be improved with embeddings)
- Provides context examples to LLM for better mapping accuracy

---

#### 3. MITREMapper Class

**Purpose**: Main analysis engine combining LLM and semantic search

##### Initialization

```python
MITREMapper(
    model_name="unsloth/Llama-3.2-3B-Instruct-bnb-4bit",
    knowledge_base=MITREKnowledgeBase()
)
```

**Key Components:**

1. **Llama 3.2 3B Model** (4-bit quantized)
    
    - Fits in ~6GB VRAM
    - Used for NLU and generation tasks
    - Loaded with BitsAndBytes quantization
2. **SentenceTransformer** (`all-MiniLM-L6-v2`)
    
    - Lightweight embedding model
    - Creates vector representations for semantic search
    - Generates technique embeddings for similarity matching

##### Core Methods

**`_create_technique_embeddings()`**

- Embeds all MITRE techniques at initialization
- Format: `"{name}: {description[:200]}"`
- Enables fast semantic search during analysis

**`_find_relevant_techniques(text, top_k=10)`**

- Uses cosine similarity between query and technique embeddings
- Returns most relevant techniques with similarity scores
- Reduces search space for LLM mapping

**`_generate_with_llm(prompt, max_tokens=2048)`**

- Wrapper for Llama model generation
- Applies chat template formatting
- Parameters:
    - `temperature=0.7`: Balanced creativity/consistency
    - `top_p=0.9`: Nucleus sampling
    - `do_sample=True`: Enable stochastic generation

---

### Analysis Pipeline

#### Step 1: Extract Threat Indicators

**Method**: `_extract_threat_indicators(report)`

Prompts LLM to extract:

1. **Threat actors**: Named groups/individuals
2. **Key behaviors**: Malicious actions described
3. **Indicators**: IPs, domains, hashes, commands
4. **Platforms**: Affected systems (Windows, Linux, etc.)

**Output**: Structured JSON with extracted information

**Fallback**: If JSON parsing fails, returns basic extraction with report snippet

---

#### Step 2: Map to TTPs

**Method**: `_map_to_ttps(report, extracted_info)`

**Process:**

1. **Retrieve similar mappings** for few-shot examples (up to 3)
2. **Find relevant techniques** via semantic search (top 15)
3. **Build context** with technique details (top 10 used)
4. **Generate prompt** with:
    - Few-shot examples from historical mappings
    - Relevant technique descriptions
    - Extracted threat information
    - Original report text
5. **Parse LLM response** to structured TTMapping objects

**LLM Task**: For each malicious behavior, identify:

- Text snippet (evidence)
- Technique ID
- Sub-technique ID (if applicable)
- Tactic phase
- Specific procedure
- Confidence score

**Fallback**: If parsing fails, creates basic mapping from top semantic match

---

#### Step 3: Generate Action Plan

**Method**: `_generate_action_plan(mappings, report)`

**For Organizations:**

- Looks up MITRE mitigations for each identified technique
- Deduplicates by mitigation ID
- Includes: mitigation name, ID, description

**For Individuals:**

- Prompts LLM to create immediate action checklist
- Focuses on:
    1. Containment (disconnect, isolate)
    2. Evidence preservation
    3. System cleanup
    4. Recovery steps
    5. Prevention measures

**Fallback**: Provides 8 generic security actions if LLM fails

---

#### Step 4: Generate Summary

**Method**: `_generate_summary(report, mappings)`

Prompts LLM to create 2-3 paragraph summary explaining:

1. **WHAT**: Type of attack
2. **HOW**: Attack methodology
3. **WHY**: Potential impact

Uses non-technical language for general audience understanding.

---

### Implementation Details

#### Memory Management

**GPU Memory Optimization:**

- 4-bit quantization reduces model size ~75%
- `device_map="auto"`: Automatic GPU/CPU allocation
- `low_cpu_mem_usage=True`: Minimizes RAM during loading
- Lightweight sentence transformer (~80MB)

**Estimated Memory Usage:**

- Llama 3.2 3B (4-bit): ~2-3GB VRAM
- Sentence embeddings: ~500MB RAM
- MITRE matrices: ~50MB RAM
- **Total**: ~3-4GB VRAM, ~1GB RAM

#### JSON Parsing Strategy

Uses regex to extract JSON from LLM responses:

```python
json_match = re.search(r'\[.*\]', response, re.DOTALL)
```

**Why?** LLMs often add explanatory text around JSON. Regex extracts just the structured data.

#### Error Handling

All major methods include try-except blocks with fallback logic:

- Failed JSON parsing → basic extraction or default values
- Missing MITRE files → empty structures with warnings
- LLM generation issues → semantic similarity fallbacks

---

### Example Usage

```python
# Initialize
kb = MITREKnowledgeBase()
mapper = MITREMapper(knowledge_base=kb)

# Analyze threat report
report = "Attackers used PowerShell to download malware..."
analysis = mapper.analyze(report)

# Access results
print(analysis.summary)
for mapping in analysis.mappings:
    print(f"{mapping.technique}: {mapping.procedure}")

# Save to JSON
with open('results.json', 'w') as f:
    json.dump(analysis.to_dict(), f, indent=2)
```

---

### Key Design Decisions

#### 1. Hierarchical Classification

Combines semantic search (fast, broad) with LLM reasoning (accurate, detailed):

- Semantic search narrows to top 10-15 techniques
- LLM performs fine-grained mapping within reduced space

#### 2. Few-Shot Learning

Provides 2-3 historical examples to LLM:

- Improves mapping consistency
- Demonstrates expected output format
- Reduces hallucination

#### 3. Confidence Scoring

Each mapping includes confidence (0.0-1.0):

- Semantic similarity score for fallbacks
- LLM-generated scores for full pipeline
- Allows filtering low-confidence mappings

#### 4. Dual Action Plans

Separates organizational vs. individual recommendations:

- Organizations: MITRE mitigations (strategic, technical)
- Individuals: Immediate checklist (tactical, actionable)

---

### Potential Improvements

#### 1. Enhanced Similarity Search

- Replace word overlap with embedding-based similarity for historical mappings
- Add BM25 or TF-IDF for keyword-based retrieval

#### 2. Multi-Stage Prompting

- Separate extraction, mapping, and validation into distinct LLM calls
- Implement self-consistency checks (multiple generations → voting)

#### 3. Relationship Extraction

- Identify attack chains (technique A → technique B)
- Build kill chain visualization

#### 4. Fine-Tuning

- Fine-tune Llama on MITRE-specific mapping tasks
- Collect user feedback for continuous improvement

#### 5. Streaming Output

- Stream LLM responses for real-time analysis
- Progressive results display during long reports

#### 6. Caching Layer

- Cache technique embeddings to disk
- Store frequent LLM responses for common patterns

---

### Dependencies

```python
# Core
torch                    # PyTorch for model inference
transformers             # HuggingFace models
sentence-transformers    # Embedding generation
bitsandbytes            # Quantization support

# Analysis
numpy                   # Numerical operations
scikit-learn            # Cosine similarity
dataclasses             # Structured data
typing                  # Type hints

# File handling
json                    # MITRE matrix parsing
pathlib                 # Path management
re                      # Regex for parsing
```

---

### File Structure

```
project/
├── attack-matrices/
│   ├── enterprise-attack.json    # MITRE Enterprise matrix
│   ├── ics-attack.json           # Industrial Control Systems
│   └── mobile-attack.json        # Mobile threats
├── mitre_mappings.json           # Historical mappings
├── app_llama_3b_quantized.ipynb  # Main implementation
└── threat_analysis_results.json  # Output file
```

---

### Performance Notes

**Typical Analysis Time:**

- Extraction: ~5-10 seconds
- Mapping: ~15-30 seconds (depends on report length)
- Action plan: ~10-15 seconds
- Summary: ~5-10 seconds
- **Total**: ~40-65 seconds per report

**Bottlenecks:**

- LLM generation (most time-consuming)
- Can be parallelized for batch processing

**Optimization Tips:**

- Batch multiple reports for embedding generation
- Use smaller `max_tokens` when possible
- Cache technique embeddings between runs

# References
## MITRE ATT&CK - Videos

1. [MITRE ATT&CK Framework](https://youtu.be/Yxv1suJYMI8?si=6HcGBvMhrwd_rcsh)
2. [Introduction to the MITRE ATT&CK Framework - HackerSploit](https://youtu.be/LCec9K0aAkM?si=SYf3x1sCsYhXQ7vy)
3. [Introduction to ATT&CK Navigator](https://www.youtube.com/watch?v=pcclNdwG8Vs)
4. [Mapping APT TTPs With MITRE ATT&CK Navigator - HackerSploit](https://youtu.be/hN_r3JW6xsY?si=P1mqsos6A7MJ8lx9)

## STIX

1. [Introduction to STIX](https://oasis-open.github.io/cti-documentation/stix/intro)

## GitHub Repositories

1. [ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data/)
2. [ATT&CK STIX Data - Usage](https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md)
3. [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2)

## Data

- [enterprise-attack](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json)
- [ics-attack](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json)
- [mobile-attack](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json)

### Documentation

1. [STIX 2 Python API](https://stix2.readthedocs.io/en/latest/)

## Best Guidelines

1. [Best Practices for MITRE ATT&CK Mapping](https://www.cisa.gov/sites/default/files/2023-01/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf)