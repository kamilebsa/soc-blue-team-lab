# SOC Blue Team Lab

Laboratório educacional de cibersegurança defensiva inspirado nas atividades de um Security Operations Center (SOC).

## Sobre o projeto

Projeto desenvolvido em Python para praticar análise de logs, identificação de atividades suspeitas, registro de eventos e monitoramento defensivo.

## Funcionalidades

- **SOC Log Analyzer:** analisa e classifica eventos de segurança.
- **Brute Force Detector:** identifica tentativas repetidas de login malsucedidas.
- **Mini SIEM API:** recebe, armazena e consulta eventos por meio de uma API REST.
- **Detecção de força bruta:** gera um alerta crítico após cinco falhas de login para o mesmo IP, conforme a regra implementada.
- **Persistência:** armazena eventos em SQLite e mantém registros em JSONL.
- **Autenticação:** protege os endpoints de eventos, alertas e estatísticas com chave de API.
- **Dashboard:** disponibiliza uma interface web para visualização de informações.
- **Eventos de rede:** inclui ferramentas experimentais de análise e coleta.
- **Testes automatizados:** utiliza Pytest para verificar funcionalidades.

## Tecnologias

- Python
- FastAPI e Uvicorn
- SQLite
- JSON e JSONL
- HTML
- Pytest
- Git e GitHub

## Estrutura do projeto

```text
soc-blue-team-lab/
├── dashboard/
│   └── index.html
├── data/
│   └── arquivos locais de eventos e banco SQLite
├── src/
│   ├── analyzer/
│   │   └── log_analyzer.py
│   ├── detector/
│   │   ├── brute_force.py
│   │   ├── network_detector.py
│   │   └── network_collector.py
│   └── siem/
│       ├── api.py
│       └── database.py
├── tests/
│   ├── test_api.py
│   ├── test_brute_force.py
│   ├── test_database.py
│   ├── test_log_analyzer.py
│   └── test_network_detector.py
├── README.md
└── .gitignore
```

## Instalação

Requisitos: Python e pip instalados.

Na raiz do projeto, instale as dependências:

```bash
python -m pip install fastapi uvicorn pytest httpx
```

## Configuração da chave de API

Os endpoints protegidos exigem a variável de ambiente `SIEM_API_KEY`.

No Linux ou Termux, configure uma chave local antes de iniciar a API:

```bash
export SIEM_API_KEY="substitua-por-uma-chave-local-forte"
```

Use uma chave própria. Não publique a chave real no GitHub nem a inclua nos arquivos do projeto.

## Como executar

Com a chave configurada, inicie a API na raiz do projeto:

```bash
python -m uvicorn src.siem.api:app --host 127.0.0.1 --port 8000
```

Acesse pelo navegador no mesmo dispositivo:

- Dashboard: http://127.0.0.1:8000/dashboard
- Documentação interativa: http://127.0.0.1:8000/docs
- Status da API: http://127.0.0.1:8000/

Os endpoints abaixo exigem o cabeçalho `X-API-Key`:

- `POST /events` — registra um evento.
- `GET /events` — consulta eventos registrados.
- `GET /alerts` — consulta eventos classificados como HIGH ou CRITICAL.
- `GET /stats` — consulta estatísticas de eventos e alertas.

Para chamar os endpoints protegidos, envie o cabeçalho `X-API-Key` com o mesmo valor configurado em `SIEM_API_KEY`.

Para executar o coletor, consulte o código em `src/detector/network_collector.py` e siga os requisitos definidos nele. A API deve estar em execução quando o coletor precisar enviar eventos.

## Testes automatizados

Execute na raiz do projeto:

```bash
python -m pytest -v
```

Na última execução registrada neste ambiente, **27 testes passaram**, sem falhas. Execute novamente para confirmar o resultado atual.

## Exemplo de detecção

A regra implementada pode gerar um evento `brute_force_detected`, com severidade `CRITICAL`, após cinco falhas de login para o mesmo IP.

Utilize somente eventos fictícios ou ambientes de laboratório autorizados.

## Limitações

Este projeto é educacional e não substitui um SIEM de produção.

- Não realiza captura completa do tráfego de rede.
- O coletor registra uma observação do IP local; isso não equivale a monitoramento completo da rede.
- As regras de detecção são simplificadas e precisam ser avaliadas em cenários mais abrangentes.
- A detecção de força bruta utiliza uma regra básica, sem correlação avançada ou janela temporal.
- A lista de eventos utilizada pela regra de detecção é mantida em memória durante a execução da API.

## Próximas melhorias

- Aprimorar a correlação e as regras de detecção.
- Expandir os testes da API e do coletor.
- Melhorar o tratamento de eventos após reinicializações.
- Documentar investigações e cenários de resposta a incidentes.

## Objetivo de aprendizagem

Praticar análise de logs, detecção baseada em regras, APIs REST, armazenamento de eventos, autenticação, testes automatizados e controle de versão.

Projeto destinado ao aprendizado de cibersegurança defensiva em ambiente de laboratório.
