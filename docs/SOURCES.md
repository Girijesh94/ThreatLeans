# Source and implementation references

Evidence feeds:

- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), acquired using the [official cisagov mirror](https://github.com/cisagov/kev-data).
- [MITRE ATT&CK](https://attack.mitre.org/), acquired as [official STIX 2.1 data](https://github.com/mitre-attack/attack-stix-data). Relationships are explicit STIX records.
- [NVD API](https://nvd.nist.gov/developers/vulnerabilities). A provider API key is optional; an unavailable/rate-limited source is recorded as a warning.
- [CVE Program JSON records](https://github.com/CVEProject/cvelistV5).
- [OWASP Top 10 2021](https://owasp.org/Top10/2021/), from [OWASP's own repository](https://github.com/OWASP/Top10).

Implementation references:

- [BGE model card and CLS pooling](https://huggingface.co/BAAI/bge-small-en-v1.5).
- [Pinned ONNX export](https://huggingface.co/Xenova/bge-small-en-v1.5/tree/ea104da/onnx).
- [OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs).
- [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages/create).
- [Ollama chat API](https://docs.ollama.com/api/chat).
- [LangGraph graph API](https://docs.langchain.com/oss/python/langgraph/graph-api).
- [Qdrant query/search](https://qdrant.tech/documentation/concepts/search/).

Snapshots are observations of these sources, not claims that their contents are permanently current. The runtime raw directory is content-addressed. Investigation exports preserve the exact cited values and hashes even after later source refreshes.
