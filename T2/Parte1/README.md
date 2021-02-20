# Análise de APKs

- Script para análise de permissões de APKs. Com esse script é possível extrair o arquivo *AndroidManifest.xml* de arquivos do tipo APK, além de obter as permissões das APKs descritas nos arquivos *AndroidManifest.xml* e exibi-las de maneira formatada na saída padrão.

## Dependências

- Python 3
- [apktool_2.5.0.jar](https://ibotpeaches.github.io/Apktool/)

## Informações gerais de uso

- É possível extrair de maneira decodificada o arquivo *AndroidManifest.xml* de um conjunto de APKs. Para isso basta utilizar o argumento **-e** e apontar para o diretório onde está o conjunto de APKs. A extração é feita no diretório *manifests* localizado no mesmo caminho do local do script, caso o diretório não exista o script o cria automaticamente. Após a extração o script faz a extração das permissões dos arquivos e exibe os resultados na saída padrão, conforme solicitado. (Para fazer a extração dos XMLs é necessário que o arquivo *apktool_2.5.0.jar* esteja no mesmo diretório que o script).

```
  python3 manifest_script.py -e /home/usuario/APKs/
```

- É possível fazer também apenas a extração das permissões de um conjunto de arquivos XMLs do tipo *AndroidManifest.xml*, sem realizar antes a extração nos APKs. Para isso basta apontar para o diretório onde os XMLs estão. Neste projeto há uma pasta já com esses arquivos chamado *manifests*. Após a extração das permissões os resultados são exibidos na saída padrão, conforme solicitado pela atividade.

```
  python3 manifest_script.py -e manifests/
```

### Ajuda do script

```
usage: manifest_script.py [-h] [-e] diretorio

Análise de APKs.

positional arguments:
  diretorio      Diretório com arquivos AndroidManifest.xml, ou com arquivos
                 APKs caso o argumento -e seja usado.

optional arguments:
  -h, --help     show this help message and exit
  -e, --extract  Extrai AndroidManifest.xml das APKs do diretório passado como
                 argumento para o diretório manifests (criado automaticamente
                 pelo script).

```

## Sistema Operacional utilizado no desenvolvimento

- Todo desenvolvimento e testes foram realizados no Sistema Operacional Ubuntu 20.04.2 LTS.

## Autor

Everton Fernando Baro
