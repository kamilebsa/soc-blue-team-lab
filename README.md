# SOC Blue Team Lab

Laboratório educacional de operações defensivas (SOC), desenvolvido em Python para praticar análise de eventos, detecção baseada em regras, persistência, autenticação de API e validação de respostas.

## Funcionalidades

- Análise e classificação de eventos de segurança.
- Detecção experimental de tentativas repetidas de login.
- API REST com FastAPI para registrar e consultar eventos.
- Autenticação por chave nas rotas protegidas.
- Persistência local em SQLite e registros JSONL.
- Dashboard web para consulta visual.
- Guardian para avaliar eventos e sugerir respostas defensivas em modo de simulação.
- Testes automatizados com Pytest.

## Arquitetura

- `src/analyzer/`: análise de logs.
- `src/detector/`: detecção e ferramentas experimentais de rede.
- `src/siem/`: API e persistência de eventos.
- `src/guardian/`: avaliação e recomendação de resposta defensiva.
- `dashboard/`: interface web.
- `tests/`: testes automatizados.
- `scripts/soc-api.sh`: controle da API local.
- `data/`: dados locais, que não devem ser publicados.

## Requisitos

- Python 3.10 ou superior.
- Dependências: FastAPI, Uvicorn, Pytest e HTTPX.

Instale as dependências, se necessário:

```bash
python -m pip install fastapi uvicorn pytest httpx
```

## Configuração segura

Configure uma chave local antes de iniciar a API. Não coloque a chave real no código, no README ou no Git.

```bash
export SIEM_API_KEY="SUBSTITUA_POR_UMA_CHAVE_FORTE"
```

Use somente uma chave própria de laboratório. Não compartilhe a saída de comandos que possam revelar segredos.

## Executar a API

Na raiz do projeto:

```bash
./scripts/soc-api.sh start
./scripts/soc-api.sh status
```

A API foi configurada para escutar em `127.0.0.1:8000`.

- Status: `http://127.0.0.1:8000/`
- Dashboard: `http://127.0.0.1:8000/dashboard`
- Documentação da API: `http://127.0.0.1:8000/docs`

As rotas de eventos, alertas e estatísticas exigem autenticação. Envie o cabeçalho `X-API-Key` usando a mesma chave configurada no ambiente.

## Testes

Execute:

```bash
python -m pytest -q
```

Na validação mais recente documentada durante o desenvolvimento, 45 testes passaram. Execute novamente para conferir o estado atual. Avisos de depreciação das dependências podem aparecer mesmo quando os testes passam.

## Persistência e reinicialização

O laboratório usa SQLite e arquivos JSONL para armazenar dados localmente. A persistência e a recuperação após reinicializações devem ser verificadas com testes específicos antes de serem consideradas garantidas para todos os tipos de evento.

Algumas regras de detecção podem manter estado apenas em memória. Esse estado pode ser perdido quando o processo reinicia; não presuma que toda correlação é persistente.

## Investigação e resposta a incidentes

Fluxo educacional sugerido:

1. Registrar o evento e seu contexto.
2. Conferir horário, origem, severidade e tipo do evento.
3. Correlacionar com outros registros disponíveis.
4. Verificar o alerta e a decisão sugerida pelo Guardian.
5. Documentar evidências, hipótese, decisão e limitações.
6. Repetir o cenário em ambiente autorizado e confirmar o resultado.

O Guardian pode sugerir ações como investigar, monitorar ou indicar um candidato a isolamento. Uma recomendação de isolamento não significa que uma máquina foi realmente isolada.

## Limitações e segurança

- Projeto educacional; não é um SIEM de produção.
- Regras de detecção simplificadas podem gerar falsos positivos e falsos negativos.
- A análise de eventos de rede não equivale à captura completa do tráfego.
- O estado mantido em memória pode não sobreviver a reinicializações.
- O modo de simulação não deve ser interpretado como execução real de resposta.
- Use somente dados fictícios, sistemas próprios ou ambientes com autorização explícita.

## Próximas melhorias

- Ampliar testes da API e do coletor de rede.
- Testar persistência e recuperação de eventos após reinicialização.
- Documentar investigações e cenários de resposta a incidentes.
- Melhorar tratamento de erros e observabilidade.
- Registrar evidências reproduzíveis para o portfólio.

## Objetivo de aprendizagem

Praticar análise de logs, detecção defensiva, APIs REST, armazenamento de eventos, autenticação, testes automatizados e controle de versão.
