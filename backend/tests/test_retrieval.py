from types import SimpleNamespace

from rank_bm25 import BM25Okapi

from threatleans.retrieval import Retriever, tokens


def test_exact_technique_does_not_substitute_subtechnique():
    engine = Retriever()
    engine.docs = [SimpleNamespace(id="ATTACK:T1566", title="T1566 Phishing", text="phishing",
                                  facts={}, source="MITRE", url="https://attack.mitre.org/techniques/T1566/",
                                  kind="technique", sha256="a", fetched_at=__import__('datetime').datetime.now()),
                   SimpleNamespace(id="ATTACK:T1566.001", title="T1566.001 Spearphishing",
                                   text="phishing phishing", facts={}, source="MITRE", url="https://attack.mitre.org/",
                                   kind="technique", sha256="b", fetched_at=__import__('datetime').datetime.now())]
    engine.bm25 = BM25Okapi([tokens(d.title + ' ' + d.text) for d in engine.docs])
    assert [r['id'] for r in engine.search('T1566')] == ['ATTACK:T1566']
    assert [r['id'] for r in engine.search('T1566.001')] == ['ATTACK:T1566.001']
