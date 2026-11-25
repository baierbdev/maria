# Guia de Execução - Maria IDS

Este documento explica passo a passo como compilar, testar (sem root) e executar em produção (com root) o **Maria IDS**.

---

## 📋 Pré-requisitos

* **Linux Kernel Headers**: correspondente à versão do seu kernel (ex: `linux-headers`).
* **Compilador e Ferramentas**: `gcc`, `make`.
* **Python**: `python3` (versão 3.8+).
* **Firewall (opcional para modo real)**: `nftables` (recomendado) ou `iptables`.

---

## 🔨 1. Compilar o Módulo de Kernel

Compile o módulo que intercepta os pacotes via `sk_buff`:

```bash
# Limpar compilações anteriores
make clean

# Compilar o módulo maria.ko
make
```

Ao finalizar, o arquivo **`maria.ko`** estará na raiz do projeto.

---

## 🧪 2. Modo de Teste e Simulação (Não precisa de Root)

Você pode testar todo o pipeline de detecção, regras de firewall simuladas e geração de logs sem privilégios de administrador.

### 2.1 Executar a suíte de testes automatizados
Valida todos os algoritmos de detecção, decodificação binária e o modelo de ML integrado:
```bash
python3 tests/test_detection.py
```

### 2.2 Executar o Daemon em modo Simulação (Dry-Run)
Abra um terminal e inicie o daemon:
```bash
python3 userspace/daemon.py --backend dryrun -v
```
No início da saída, anote o **PID do Netlink** exibido, por exemplo:
```text
[INFO] Netlink socket bound with PID 21228 on unit 2
```

### 2.3 Injetar Tráfego Sintético de Ataque
Em outro terminal, injete cenários de tráfego (port scan, injeção de SQL, web shell, scan XMAS, etc.) passando o PID anotado:
```bash
python3 tests/simulate_traffic.py --pid 21228 --scenario all
```

### 2.4 Inspecionar os Logs Gerados
Veja as ações de bloqueio e os registros forenses:
* **Log de Ações do Firewall**:
  ```bash
  cat logs/firewall.log
  ```
* **Log Detalhado de Pacotes Maliciosos (JSONL)**:
  ```bash
  cat logs/malicious_packets.jsonl
  ```

---

## 🚀 3. Modo de Produção / Tráfego Real (Requer Root)

Neste modo, o módulo intercepta o tráfego real das placas de rede e bloqueia conexões maliciosas no sistema operacional.

### 3.1 Carregar o Módulo no Kernel
```bash
# capture_loopback=1 é opcional (permite capturar tráfego local 127.0.0.1 em testes)
sudo insmod maria.ko capture_loopback=1

# Confirmar se o módulo foi carregado
dmesg | tail -n 10
```

### 3.2 Iniciar o Daemon de Detecção
Escolha o backend de firewall desejado:

#### Opção A: Usando nftables (Recomendado no Linux moderno)
```bash
sudo python3 userspace/daemon.py --backend nftables
```

#### Opção B: Usando iptables
```bash
sudo python3 userspace/daemon.py --backend iptables
```

### 3.3 Opções e Parâmetros Úteis do Daemon
Você pode customizar o comportamento com argumentos na linha de comando:
* `--ttl <segundos>`: Tempo de bloqueio do IP no firewall (padrão: `300` segundos; use `0` para bloqueio permanente).
* `--port-scan-threshold <n>`: Número de portas únicas acessadas em 5s para disparar bloqueio (padrão: `8`).
* `--syn-flood-threshold <n>`: Número de pacotes SYN em 2s para disparar bloqueio de flood (padrão: `40`).
* `--ml-model <caminho>`: Caminho para um modelo LightGBM treinado (ex: `userspace/models/maria_lgbm_model.txt`).
* `-v`, `--verbose`: Ativa logs detalhados de depuração para cada pacote.

Exemplo avançado:
```bash
sudo python3 userspace/daemon.py --backend nftables --ttl 600 -v
```

### 3.4 Descarregar o Módulo e Parar o Sistema
1. Pressione `Ctrl+C` no terminal do daemon. Ele fará o *flush* e a limpeza automática de todas as regras criadas no firewall.
2. Descarregue o módulo do kernel:
   ```bash
   sudo rmmod maria
   ```

---

## 🧠 4. Treinamento de Modelo de ML com Dataset Externo (Opcional)

Se você baixar datasets públicos como **UNSW-NB15** ou **CIC-IDS2017**:

1. Instale as bibliotecas necessárias para treino:
   ```bash
   pip install lightgbm pandas scikit-learn
   ```

2. Execute o script de treinamento:
   ```bash
   python3 userspace/train_model.py --data UNSW_NB15_training-set.csv --output userspace/models/maria_lgbm_model.txt
   ```

3. Passe o modelo treinado para o daemon:
   ```bash
   sudo python3 userspace/daemon.py --backend nftables --ml-model userspace/models/maria_lgbm_model.txt
   ```
