# Scope Guardrails

## Do not add without a new measured requirement

- Neo4j / graph DB
- ChromaDB / Pinecone / FAISS
- RAG or embeddings
- multiple autonomous agents
- Kubernetes / Helm
- Kafka / RabbitMQ
- service mesh
- second policy engine
- custom workflow engine
- real AWS mutations
- generic shell MCP tool
- browser-use agent
- long-term memory

## Why

The hiring signal is **safe tool execution under adversarial LLM behavior**, not architecture breadth.

Complexity is justified around action identity, policy enforcement, capability scoping, exact-action approval, durable recovery, idempotency, sandboxing, adversarial eval, and auditability.

Before adding any service/dependency, answer:
1. What current requirement cannot be met without it?
2. Which issue requires it?
3. What simpler option was rejected?
4. How will value be measured?
5. What operational/security cost does it add?
