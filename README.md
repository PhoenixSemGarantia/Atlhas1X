# Atlhas1x

Atlhas1x é uma ferramenta simples, somente de leitura, para auditoria de segurança do Windows.

Current version: v0.4

Esta versão adiciona SMB security checks, local password policy auditing, Guest account detection, local account password configuration review e Windows security service checks aos relatórios HTML offline.

The Atlhas1x Security Score is an internal project metric designed to provide a simple overview of detected security findings. It is not an official Microsoft, NIST, CIS or industry-standard score.

O programa não altera Firewall, Defender, UAC, RDP, usuários, políticas nem qualquer outra configuração do Windows.

O Atlhas1x não exige pacotes Python adicionais. Se uma consulta ou recurso não estiver disponível em determinada versão do Windows, o check correspondente é registrado como `UNKNOWN` ou `NOT AVAILABLE`, sem interromper a auditoria inteira.

## Instalar e executar no Windows

Para a forma mais simples, abra `instalar_atlhas1x.bat`. Ele copia o projeto para a Área de Trabalho, verifica se o Python está disponível e, quando necessário, baixa uma cópia portátil oficial do Python apenas para a pasta do Atlhas1x. Em seguida, cria a pasta de relatórios e executa a auditoria.

Em execuções seguintes, o instalador reconhece os arquivos já instalados, verifica somente atualizações e pergunta se a auditoria deve ser executada. Ele não faz alterações nas configurações de segurança do Windows.

Depois de instalado, use `Executar_Atlhas1x.bat` para executar novas auditorias por duplo clique. Não é necessário abrir o arquivo `atlhas1x.py` diretamente. O lançador mostra três níveis de relatório: básico (resumo), intermediário (valores coletados) e avançado (detalhes técnicos e critérios).

Também é possível abrir o PowerShell no diretório do projeto e executar manualmente:

```powershell
python atlhas1x.py
```

O relatório será criado em `reports/atlhas1x_nivel_AAAA-MM-DD_HHMMSS.html`. Cada modo gera um arquivo separado.

Se alguma informação não puder ser consultada, o Atlhas1x deve exibir `[UNKNOWN]` em vez de interromper a execução.
