# Atlhas1x — Auditoria de Segurança do Windows

[English](README.md) · **Português**

O Atlhas1x é uma ferramenta local e somente leitura para auditoria de configurações de segurança do Windows. Ele coleta metadados de segurança, classifica achados e gera relatórios HTML que funcionam sem internet.

## Início rápido

```powershell
git clone https://github.com/PhoenixSemGarantia/Atlhas1X.git
cd Atlhas1X
python -m pip install -r requirements.txt
python atlhas1x.py --report intermediate
```

Também é possível abrir `Atlhas1x.bat` para usar o inicializador guiado no Windows.

## O que o Atlhas1x faz

- Audita Defender, Firewall, contas, políticas, RDP, SMB, BitLocker, atualizações e hardening do Windows.
- Produz relatórios Basic, Intermediate e Advanced offline.
- Mostra Security Score, risco geral, severidade, confiança e cobertura da auditoria.
- Inventaria itens relevantes de persistência, processos, portas e conexões.
- Usa YARA localmente quando `yara-python` estiver disponível.

O Atlhas1x não altera configurações do Windows, não executa arquivos encontrados e não envia relatórios, hashes ou dados pessoais para a internet.

Consulte o [README principal em inglês](README.md) para a documentação completa e os documentos em [`docs/`](docs/).

> O Security Score é uma métrica interna do projeto; ele não é um padrão oficial da Microsoft, NIST, CIS ou outra organização.

## Segurança e limites

Achados exigem revisão humana. Indicadores suspeitos ou correspondências YARA não confirmam malware por conta própria. Recursos podem aparecer como `UNKNOWN`, `NOT AVAILABLE` ou `ACCESS DENIED` conforme a versão do Windows, permissões e políticas locais.

Para reportar uma vulnerabilidade do próprio projeto, leia [SECURITY.md](SECURITY.md). Para contribuir, leia [CONTRIBUTING.md](CONTRIBUTING.md).
