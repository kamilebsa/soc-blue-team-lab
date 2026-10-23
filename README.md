SOC Blue Team Lab

Laboratório educacional de cibersegurança defensiva, inspirado nas atividades de um Security Operations Center (SOC).

Sobre o projeto

O SOC Blue Team Lab é um projeto desenvolvido para praticar análise de logs, detecção de atividades suspeitas, registro de eventos de segurança e visualização de alertas.

O objetivo é construir uma base prática em Python, APIs e monitoramento defensivo, com foco em atividades relacionadas a SOC e Blue Team.

Funcionalidades

- SOC Log Analyzer: analisa eventos de segurança em arquivos JSONL e gera relatórios.
- Brute Force Detector: identifica padrões de tentativas repetidas de login malsucedidas.
- Mini SIEM API: recebe eventos, armazena registros e disponibiliza consultas por API.
- Detecção automática: gera um alerta crítico quando são registradas cinco falhas de login para o mesmo IP.
- Dashboard: apresenta estatísticas, eventos recentes e alertas de segurança.
- Persistência: mantém os eventos registrados em arquivo JSONL após reiniciar a API.

Tecnologias utilizadas

- Python
- FastAPI
- Uvicorn
- Pytest
- JSON e JSONL
- HTML
- Git

Estrutura do projeto

soc-blue-team-lab/
├── data/
│   ├── security_events.jsonl
│   └── siem_events.jsonl
├── dashboard/
│   └── index.html
├── reports/
├── src/
│   ├── analyzer/
│   │   └── log_analyzer.py
│   ├── detector/
│   │   └── brute_force.py
│   └── siem/
│       └── api.py
└── tests/
    ├── test_log_analyzer.py
    └── test_brute_force.py

Como executar

Instale as dependências necessárias no ambiente Python:

pip install fastapi uvicorn pytest

Na raiz do projeto, inicie a API:

python -m uvicorn src.siem.api:app --host 127.0.0.1 --port 8000

Acesse no navegador:

- Dashboard: http://127.0.0.1:8000/dashboard
- Documentação interativa da API: http://127.0.0.1:8000/docs
- Eventos: http://127.0.0.1:8000/events
- Alertas: http://127.0.0.1:8000/alerts
- Estatísticas: http://127.0.0.1:8000/stats

Mantenha o servidor em execução enquanto acessa essas páginas.

Executar os testes

python -m pytest -v

Última validação registrada: 8 testes passaram.

Exemplo de detecção

Durante os testes do laboratório, cinco falhas de login foram registradas para o IP fictício "198.51.100.25".

O sistema gerou um evento "brute_force_detected" com severidade "CRITICAL".

Os endereços utilizados nos exemplos são reservados para documentação e testes.

Objetivos de aprendizagem

- Análise e classificação de logs.
- Identificação de padrões de autenticação suspeitos.
- Desenvolvimento e consulta de APIs.
- Armazenamento persistente de eventos.
- Visualização de alertas de segurança.
- Testes automatizados com Pytest.
- Controle de versão com Git.

Limitações atuais

Este é um laboratório educacional. Ele não substitui um SIEM de produção e ainda não está integrado a redes ou equipamentos reais. As regras de detecção são simplificadas e podem precisar de ajustes para cenários reais.

Próximos passos

- Ampliar a análise de eventos de rede.
- Criar testes automatizados para a API.
- Melhorar as regras de correlação e detecção.
- Documentar novos cenários de investigação.

Aviso

Projeto destinado ao aprendizado de cibersegurança defensiva, análise de logs e monitoramento de eventos em ambiente de laboratório.
