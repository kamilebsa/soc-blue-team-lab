SOC Blue Team Lab

Laboratório educacional de cibersegurança defensiva inspirado nas atividades de um Security Operations Center (SOC).

Sobre o projeto

O SOC Blue Team Lab é um projeto prático desenvolvido em Python para estudar análise de logs, detecção de atividades suspeitas, registro de eventos e monitoramento defensivo.

Funcionalidades

- SOC Log Analyzer: analisa eventos de segurança armazenados em arquivos JSONL.
- Brute Force Detector: identifica padrões de tentativas repetidas de login malsucedidas.
- Mini SIEM API: recebe, armazena e consulta eventos de segurança.
- Detecção de força bruta: gera alertas quando uma regra identifica tentativas suspeitas.
- Dashboard: apresenta estatísticas, eventos recentes e alertas.
- Coletor de eventos de rede: registra uma observação do IP local e envia o evento à API.
- Persistência: mantém os eventos registrados em arquivos JSONL.
- Testes automatizados: verifica funcionalidades com Pytest.

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
│   └── arquivos locais de eventos
├── src/
│   ├── analyzer/
│   │   └── log_analyzer.py
│   ├── detector/
│   │   ├── brute_force.py
│   │   ├── network_detector.py
│   │   └── network_collector.py
│   └── siem/
│       └── api.py
├── tests/
│   ├── test_log_analyzer.py
│   ├── test_brute_force.py
│   └── test_network_detector.py
├── README.md
└── .gitignore

Como executar

Instale as dependências:

pip install fastapi uvicorn pytest

Na raiz do projeto, inicie a API:

python -m uvicorn src.siem.api:app --host 127.0.0.1 --port 8000

Mantenha a API em execução. Acesse pelo navegador:

- Dashboard: http://127.0.0.1:8000/dashboard
- Documentação da API: http://127.0.0.1:8000/docs
- Eventos: http://127.0.0.1:8000/events
- Alertas: http://127.0.0.1:8000/alerts
- Estatísticas: http://127.0.0.1:8000/stats

Para executar o coletor, abra outra sessão do Termux, entre na pasta do projeto e execute:

python -m src.detector.network_collector

Executar os testes

Na pasta do projeto, execute:

python -m pytest -v

O projeto passou anteriormente em 12 testes automatizados. Execute novamente para confirmar o resultado atual.

Exemplo de detecção

Durante os testes, cinco falhas de login para o mesmo IP fictício podem acionar um alerta "brute_force_detected" com severidade "CRITICAL", conforme a regra configurada.

Os endereços usados nos exemplos são reservados para documentação e testes.

Objetivos de aprendizagem

- Análise e classificação de logs.
- Identificação de padrões de autenticação suspeitos.
- Desenvolvimento e consulta de APIs.
- Armazenamento persistente de eventos.
- Visualização de alertas de segurança.
- Testes automatizados com Pytest.
- Controle de versão com Git.

Limitações atuais

Este é um laboratório educacional. Não substitui um SIEM de produção e não realiza captura completa do tráfego de rede. O coletor atual registra uma observação do IP local e envia o evento à API. As regras de detecção são simplificadas e precisam de validação em cenários reais.

Próximos passos

- Ampliar a análise de eventos de rede.
- Criar testes automatizados para a API.
- Melhorar as regras de correlação e detecção.
- Documentar novos cenários de investigação.

Aviso

Projeto destinado ao aprendizado de cibersegurança defensiva, análise de logs e monitoramento de eventos em ambiente de laboratório.
