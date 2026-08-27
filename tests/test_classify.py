"""Testes de agents.classify(): garante que perguntas com intenção didática
explícita ("explica X", "o que é X") caem no agente 'learning' mesmo quando
X é um termo que também aparece nos buckets de tópico (security/network/system) —
regressão do bug em que 'explica firewall'/'o que é nmap' eram roteados pra
'security' porque esse bucket casava primeiro."""

from agents import classify


def test_explaining_a_security_term_routes_to_learning():
    assert classify("explica o que é firewall") == "learning"
    assert classify("o que é nmap") == "learning"
    assert classify("explica scan de portas") == "learning"
    assert classify("o que é hardening") == "learning"
    assert classify("o que é backup") == "learning"


def test_bare_topic_mentions_still_route_to_their_own_bucket():
    assert classify("escaneie a porta 22 do host") == "security"
    assert classify("mostra as interfaces de rede") == "network"
    assert classify("quanto de cpu está em uso") == "system"


def test_unmatched_prompt_falls_back_to_network():
    assert classify("oi, tudo bem?") == "network"
