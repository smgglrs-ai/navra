# Heuristics

Reusable reasoning patterns. Each module contains facets —
specific, actionable principles that personas reference by
`module: facet_name` in their YAML definitions.

## Categories

### Architecture & Design
| Module | Focus |
|--------|-------|
| `ai_architecture_patterns` | AI system design patterns |
| `ai_orchestration_design` | Multi-agent orchestration |
| `architectural_patterns` | General software architecture |
| `software_architecture` | Component design, coupling, cohesion |
| `systems_thinking` | Interdependencies, second-order effects |

### Engineering Practice
| Module | Focus |
|--------|-------|
| `craftsmanship` | Code quality standards |
| `code_review_skills` | Review methodology |
| `collaborative_coding` | Team coding patterns |
| `debugging` | Root cause analysis, isolation |
| `development_workflow` | TDD, iterative development, git |
| `python_expertise` | Python-specific patterns |
| `performance` | Optimization, profiling, caching |

### Analysis & Research
| Module | Focus |
|--------|-------|
| `analyst_heuristics` | Pattern recognition, insight extraction |
| `critical_methodology` | Logical rigor, bias detection |
| `data_analysis` | Statistical methods, trend identification |
| `grounded_research_protocol` | Evidence-based investigation |
| `research_methodology` | Systematic information gathering |
| `semantic_analysis` | Language register, tone consistency |
| `result_synthesis` | Combining multiple sources coherently |

### Quality & Validation
| Module | Focus |
|--------|-------|
| `error_scrutiny` | Failure mode analysis |
| `evaluation_methodology` | Scoring, assessment frameworks |
| `pre_flight_check` | Pre-execution validation |
| `watchdog_heuristics` | Anomaly detection, drift monitoring |

### Security & Safety
| Module | Focus |
|--------|-------|
| `security` | General security principles |
| `security_heuristics` | Threat modeling, vulnerability assessment |

### Leadership & Management
| Module | Focus |
|--------|-------|
| `leader_heuristics` | Task routing, delegation decisions |
| `problem_decomposition` | Breaking complex problems down |
| `product_management` | Roadmap, prioritization |
| `project_orchestration` | Team coordination, milestone tracking |

### Communication & UX
| Module | Focus |
|--------|-------|
| `accessibility` | Inclusive design checks |
| `clarity` | Semantic precision, readability |
| `cognitive_load` | Information chunking, progressive disclosure |
| `feedback` | Error communication, success signals |

### Identity & Mindset
| Module | Focus |
|--------|-------|
| `core_mindsets` | Proactive architect, adaptive recoverer |
| `mission_and_identity` | System purpose and values |
| `viability_challenger` | Feasibility stress-testing |

## Adding a heuristic

```yaml
heuristic_name: my_domain
description: "What this module covers"
facets:
  - facet_name: specific_principle
    display_name: "Human-Readable Name"
    content: |
      Detailed instruction for this facet...
references:
  - description: "Source"
    source: "https://..."
```
