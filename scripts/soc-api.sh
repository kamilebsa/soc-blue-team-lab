#!/data/data/com.termux/files/usr/bin/bash

cd "$HOME/soc-blue-team-lab" || exit 1

KEY_FILE="$HOME/.config/soc-blue-team-lab/api_key"
if [ ! -r "$KEY_FILE" ]; then
  echo "ERRO: chave local ausente ou ilegível: $KEY_FILE"
  exit 1
fi
export SIEM_API_KEY="$(tr -d '\r\n' < "$KEY_FILE")"
if [ -z "$SIEM_API_KEY" ]; then
  echo "ERRO: o arquivo da chave está vazio."
  exit 1
fi

case "${1:-start}" in
  start)
    if curl --max-time 2 -fsS -H "X-API-Key: $SIEM_API_KEY" \
      http://127.0.0.1:8000/stats >/dev/null 2>&1; then
      echo "SOC API já está respondendo."
      exit 0
    fi

    if curl --max-time 2 -s \
      -o /dev/null -w '%{http_code}' \
      http://127.0.0.1:8000/ | grep -qE '^[1-5][0-9][0-9]$'; then
      echo "A porta 8000 já responde, mas a API não passou no teste /stats."
      echo "Consulte: bash scripts/soc-api.sh status"
      exit 1
    fi

    nohup python -m uvicorn src.siem.api:app \
      --host 127.0.0.1 --port 8000 \
      >> uvicorn.log 2>&1 </dev/null &

    for i in $(seq 1 10); do
      sleep 1
      if curl --max-time 2 -fsS -H "X-API-Key: $SIEM_API_KEY" \
        http://127.0.0.1:8000/stats >/dev/null 2>&1; then
        echo "SOC API iniciada com sucesso."
        echo "Dashboard: http://127.0.0.1:8000/dashboard"
        exit 0
      fi
    done

    echo "A API não respondeu. Últimas linhas do log:"
    tail -n 25 uvicorn.log
    exit 1
    ;;

  status)
    echo "=== API ==="
    curl --max-time 3 -s -o /dev/null \
      -w "HTTP %{http_code}\n" \
      http://127.0.0.1:8000/

    echo "=== AUTENTICACAO ==="
    curl --max-time 3 -s -o /dev/null \
      -w "Stats sem chave: HTTP %{http_code}\n" \
      http://127.0.0.1:8000/stats

    echo "=== GUARDIAN ==="
    curl --max-time 3 -s -o /dev/null \
      -w "Guardian sem chave: HTTP %{http_code}\n" \
      http://127.0.0.1:8000/guardian

    echo "Esperado com autenticacao ativa: 401 nas rotas protegidas."
    ;;

  logs)
    tail -n 40 uvicorn.log
    ;;

  *)
    echo "Uso: bash scripts/soc-api.sh {start|status|logs}"
    exit 2
    ;;
esac
