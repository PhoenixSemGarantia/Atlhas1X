# Atlhas1x

Atlhas1x é uma ferramenta local, somente de leitura, para auditoria de segurança do Windows.

Current version: v1.2
Status: Stable

Atlhas1x is a local Windows security scanner that audits system security configurations, identifies potential security issues, calculates an internal security score and generates offline HTML reports.

O Atlhas1x é uma ferramenta local de auditoria de segurança do Windows. Ele não é monitoramento contínuo, agente em background, EDR, SIEM ou serviço cloud.

## Features

- Defender, Firewall, account, update, network and Windows hardening checks.
- Basic, Intermediate and Advanced offline HTML reports.
- Security Score, finding confidence and Scan Completeness.
- Read-only local collection with isolated check failures.
- No cloud services or automatic remediation; YARA is an optional local
  dependency.
- Focused suspicious-activity heuristics for persistence, process paths,
  recent files and process/listener relationships.
- Optional local YARA matching, SHA-256 identification and Authenticode
  metadata for files already selected by the scanner.

O programa não altera Firewall, Defender, UAC, RDP, usuários, políticas nem qualquer outra configuração do Windows.

O Atlhas1x usa a biblioteca padrão do Python para os checks principais. A
dependência `yara-python` adiciona somente a correspondência YARA local; se ela
não estiver disponível, o check correspondente é registrado como `NOT AVAILABLE`
sem interromper a auditoria inteira.

## Detection Accuracy & Validation

O Atlhas1x v1.2 correlaciona indicadores locais como locais temporários,
persistência por startup/tarefa/serviço, listeners de rede, metadados recentes,
assinatura digital e, opcionalmente, correspondências YARA. Ele examina somente
arquivos já relacionados a esses itens; nunca percorre todo o disco, executa um
arquivo ou envia dados para a internet.

Esta versão reduz ruído usando contexto positivo: assinatura válida, caminho
esperado do Windows/Program Files e componente conhecido reduzem a relevância
heurística. AppData, arquivo recente, assinatura ausente ou porta em escuta não
geram alerta alto isoladamente. Correspondências YARA genéricas também são
tratadas com cautela e exigem revisão manual.

Atlhas1x uses heuristic indicators to identify items that may require manual
review. A suspicious finding or a YARA match does not mean that malware or a
backdoor has been confirmed.

`yara-python` é opcional em tempo de execução: sem a biblioteca ou sem regras
locais, o scanner continua com as heurísticas. As regras próprias ficam em
`rules/local/`; regras de terceiros podem ficar em
`rules/third_party/yara-rules/` e sua origem/licença estão documentadas em
`RULE_SOURCES.md`. O scan nunca baixa ou atualiza regras automaticamente.

Os inventários de processos e rede usam apenas metadados locais necessários para a auditoria. O Atlhas1x não lê memória de processos, conteúdo de tráfego, senhas, cookies, tokens ou credenciais; também não encerra processos, bloqueia conexões ou realiza port scanning.

Nesta versão estável, o scan inclui SmartScreen, Memory Integrity, VBS, Credential Guard, proteção LSASS, hardening do Defender, ASR e Controlled Folder Access, além dos checks de Defender, Firewall, PowerShell, proxy, DNS, interfaces de rede, Windows Update, contas, RDP e portas locais. Uma informação indisponível é exibida como `UNKNOWN`, `NOT AVAILABLE` ou `ACCESS DENIED`, sem interromper o restante da auditoria.

Alguns recursos de hardening dependem da edição do Windows, hardware, virtualização e configuração local. `NOT AVAILABLE` é informativo e não reduz a pontuação. A análise de idade das assinaturas do Defender usa um limite interno de sete dias para revisão; não é uma regra oficial da Microsoft.

## Installation

Para a forma mais simples, abra `instalar_atlhas1x.bat`. Ele copia o projeto para a Área de Trabalho, verifica se o Python está disponível e, quando necessário, baixa uma cópia portátil oficial do Python apenas para a pasta do Atlhas1x. Em seguida, cria a pasta de relatórios e executa a auditoria.

O instalador também tenta preparar `yara-python` quando o Python disponível
possui `pip`. Se isso não for possível, a instalação continua normalmente e o
rodapé do relatório mostra que YARA está indisponível, com explicação e link
para as regras locais suportadas.

Em execuções seguintes, o instalador reconhece os arquivos já instalados, verifica somente atualizações e pergunta se a auditoria deve ser executada. Ele não faz alterações nas configurações de segurança do Windows.

Depois de instalado, use `Executar_Atlhas1x.bat` para executar novas auditorias por duplo clique. Não é necessário abrir o arquivo `atlhas1x.py` diretamente. O lançador mostra três níveis de relatório: básico (resumo), intermediário (valores coletados) e avançado (detalhes técnicos e critérios).

A instalação e a auditoria são fluxos separados: após concluir a instalação, a janela do instalador fecha. A auditoria usa uma interface gráfica com barra de carregamento e abre o relatório HTML ao terminar.

## Usage

```text
Atlhas1x/
├── atlhas1x.py                 # auditoria local e geração de relatórios
├── instalar_atlhas1x.bat       # instalação guiada
├── Executar_Atlhas1x.bat       # lançador diário
├── scripts/                    # interface gráfica e seleção de modo
├── reports/                    # relatórios HTML gerados localmente
├── README.md
└── TODO.md
```

Também é possível abrir o PowerShell no diretório do projeto e executar manualmente:

```powershell
pip install -r requirements.txt
python atlhas1x.py --report intermediate
```

Se `yara-python` não puder ser instalado naquela máquina, o scanner permanece
funcional e informa que a etapa YARA está indisponível; nenhuma heurística é
interrompida por isso.

O comando sem argumentos também gera o relatório `intermediate`. Use `--report basic`, `--report intermediate` ou `--report advanced`; `--version` mostra a versão instalada e `--help` apresenta a ajuda curta.

Os relatórios são criados em `reports/atlhas1x_nivel_AAAA-MM-DD_HHMMSS.html`.

## Report Levels

- Basic: sistema, score, risco, cobertura do scan e achados importantes.
- Intermediate: todos os achados com descrições e recomendações.
- Advanced: evidências normalizadas, tempos dos módulos e inventários técnicos.

## Scan Accuracy

O Atlhas1x usa contexto e fontes estruturadas do Windows quando disponíveis. Um finding informa `confidence` (HIGH, MEDIUM ou LOW). Estados `UNKNOWN`, `NOT AVAILABLE` e `ACCESS DENIED` não são classificados como configurações desabilitadas.

## Detection Confidence

O `Suspicion Score` é uma medida interna de relevância dos indicadores
correlacionados, de `0` a `100`; ele não é probabilidade de malware. O relatório
Advanced mostra os pesos positivos e redutores aplicados, incluindo
considerações de possível falso positivo.

## Validation Suite

Execute `python -m unittest discover -s tests -v` para validar funções de score,
caminhos, parsing seguro, YARA local, HTML offline e regressões de falsos
positivos. Consulte [TESTING.md](TESTING.md) para a validação real na VM Windows.

## Security Score and Scan Completeness

The Atlhas1x Security Score is an internal project metric designed to provide a simple overview of confirmed findings. It is not an official Microsoft, CIS, NIST or industry-standard security score. `Scan Completeness` mede somente a cobertura dos checks executados; ela não aumenta nem reduz o Security Score.

## Supported Environment and Limitations

O scanner foi feito para Windows e usa comandos nativos e PowerShell quando disponíveis. Alguns recursos dependem da edição do Windows, hardware, virtualização, antivírus ativo e permissões atuais. O scan continua sem privilégios administrativos, mas alguns dados podem ficar indisponíveis.

## Screenshots

Os relatórios HTML são locais e funcionam sem conexão com a internet.

## Disclaimer

Atlhas1x is an auditing tool and does not automatically modify or remediate Windows security settings. Findings should be reviewed in the context of the system where the scan was performed.
