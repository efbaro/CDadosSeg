# Análise de arquivos *Portable Executable* (PE)

- Script para análise de binários PE. O script *enum_.py* enumera as seções dos binários, exibindo todas as seções e destacando suas permissões, além de destacar as seções executáveis. Já o script *compara.py* faz a comparação entre dois binários, destacando as seções comuns a ambos, quais seções pertencem a somente a cada binário.

## Dependências

- Python 3
- [pefile](https://github.com/erocarrera/pefile)

## Informações gerais de uso

### *enum_.py*

- O script aceita como entrada um arquivo binário ou um diretório com vários binários. O script é capaz de localizar no diretório somete os arquivos que são do tipo binário PE. O script faz a extração dos dados dos arquivos e exibe os resultados na saída padrão, conforme solicitado na atividade.

```
  python3 enum_.py /home/usuario/EXEs/
```

sendo */home/usuario/EXEs/* um caminho para o diretório com vários binários PE.

```
  python3 enum_.py /home/usuario/EXEs/Settings.exe
```

sendo */home/usuario/EXEs/Settings.exe* um caminho para um arquivo binário PE.

- Ajuda do script:

```
usage: enum_.py [-h] caminho

Análise de binários Portable Executable (PE).

positional arguments:
  caminho     Diretório com arquivos binários do tipo Portable Executable (PE)
              ou arquivo binário do tipo PE.

optional arguments:
  -h, --help  show this help message and exit

```

### *compara.py*

- O script necessita como entrada de dois arquivos do tipo binário PE. O script faz a extração dos dados dos arquivos e exibe os resultados das comparações na saída padrão, conforme solicitado na atividade.

```
  python3 compara.py Settings.exe Launcher.exe
```

sendo *Settings.exe* e *Launcher.exe* arquivos do tipo binário PE.

- Ajuda do script:

```
usage: compara.py [-h] arquivo_1 arquivo_2

Análise de binários Portable Executable (PE).

positional arguments:
  arquivo_1   Arquivo binário do tipo PE.
  arquivo_2   Arquivo binário do tipo PE.

optional arguments:
  -h, --help  show this help message and exit
```


## Sistema Operacional utilizado no desenvolvimento

- Todo desenvolvimento e testes foram realizados no Sistema Operacional Ubuntu 20.04.2 LTS.

## Autor

Everton Fernando Baro
