"""
    Autor: Everton Fernando Baro
    Data: 18/02/2021
"""
import sys
import os
import pefile
import argparse

def imprimir_permissao(nome_secao, permissoes):
    """
    Imprime a permissão da seção de maneira formatada

    Parameters
    ----------
    nome_secao : str
        Nome da seção

    permissoes: list
        Lista com três posições de valores booleanos. A primeira posição
        representa a permissão de leitura a segunda de escrita e a
        terceira de execução, sendo True para permitido e False para
        não permitido. Ex.:[True, False, True], leitura sim, escrita não
        e execução sim.
    """
    str_permissoes = ['-','-','-']
    str_permissoes_aux = ['r','w','x']
    for i in range(len(permissoes)):
        if permissoes[i]:
            str_permissoes[i] = str_permissoes_aux[i]

    str_permissoes = ''.join(str_permissoes)
    str_executavel = permissoes[2] and 'executável' or 'não executável'

    print('{:<6} {:<10.10} {:>15} {:<3}'.format('Seção:', nome_secao, str_executavel, str_permissoes))


def get_binarios_pe(caminho):
    """
    Retorna um dicionário com todos os arquivos Portable Executable (PE)
    pertencentes ao diretório passado como parâmetro.

    Parameters
    ----------
    caminho : str
        Caminho para diretório onde estão os arquivos.

    Returns
    -------
    dict
        Dicionário em que a chave é o nome do arquivo e o valor é o
        objeto pe.
    """

    pe_files = {}

    list_dir = os.listdir(caminho)
    # Percorre lista de diretórios e arquivos
    for d in list_dir:
        # Verifica se é arquivo
        if os.path.isfile(caminho + '/' + d):
            try:
                pe  = pefile.PE(caminho + '/' + d)
            except pefile.PEFormatError:
                # Ignora o arquivo caso não seja to tipo Portable Executable (PE)
                continue
            else:
                pe_files[d] = pe
    return pe_files


def imprime_arquivo(caminho):
    """
    Imprime as permissões das seções de maneira formatada, além
    de uma lista com as seções que são executáveis.

    Parameters
    ----------
    caminho : str
        Caminho para o arquivo.

    Returns
    -------
    list
        Lista com os nomes das seções que são executáveis no arquivo.
    """
    secoes_executaveis = []
    try:
        pe  = pefile.PE(caminho)

        for i in range(len(pe.sections)):
            nome_secao = pe.sections[i].Name.decode('utf-8')
            nome_secao = nome_secao.replace('\x00','')
            permissoes = [pe.sections[i].IMAGE_SCN_MEM_READ,
                          pe.sections[i].IMAGE_SCN_MEM_WRITE,
                          pe.sections[i].IMAGE_SCN_MEM_EXECUTE]
            imprimir_permissao(nome_secao, permissoes)

            # Verifica se a seção é executável para armazenar na lista
            if pe.sections[i].IMAGE_SCN_MEM_EXECUTE:
                secoes_executaveis.append(nome_secao)

        print("\nSeções executáveis:",secoes_executaveis)
        print("#"*60,'\n')

    except pefile.PEFormatError:
        print('O arquivo', caminho, 'não é um arquivo binário do tipo Portable Executable (PE)')

    return secoes_executaveis


def imprime_arquivos_caminho(caminho):
    """
    Imprime as permissões das seções de cada arquivo maneira formatada, além
    de um dicionário com as seções que são executáveis.

    Parameters
    ----------
    caminho : str
        Caminho para diretório onde estão os arquivos.
    """

    dic = {}

    dic_bin_pe = get_binarios_pe(caminho)

    # Verifica se há arquivos do tipo Portable Executable (PE)
    if len(dic_bin_pe) == 0:
        print('Não há arquivos do tipo  Portable Executable (PE) no diretório', caminho)
    else:
        # Percorre os arquivos e imprime de maneira formatada
        # as permissões das seções e a lista de seções executáveis.
        for key, value in dic_bin_pe.items():
            print("Seções pertencentes ao arquivo:", key)
            secoes_executaveis = imprime_arquivo(caminho + '/' + key)
            dic[key] = secoes_executaveis

    print("\nDicionário com a relação entre arquivos e seções executáveis\n")
    print('{:<20} {:<60}'.format('Arquivo', 'Seções executáveis'))
    for key, value in dic.items():
        print('{:<20} {:<60}'.format(key, str(value)))

def main():
    """
    Inicia a execução do programa
    """

    parser = argparse.ArgumentParser(description='Análise de binários Portable Executable (PE).')
    parser.add_argument('caminho', type=str, help='Diretório com arquivos ' + \
                        'binários do tipo Portable Executable (PE) ou arquivo ' + \
                        'binário do tipo PE.')
    args = parser.parse_args()

    caminho = args.caminho

    # Verifica se arquivo ou diretório existe
    if os.path.exists(caminho):
        # Verifica se o caminho é um arquivo
        if os.path.isfile(caminho):
            imprime_arquivo(caminho)
        # Verifica se o caminho é um diretório
        elif os.path.isdir(caminho):
            imprime_arquivos_caminho(caminho)
        else:
            print(caminho + ':', 'Deve ser um arquivo ou diretório válido')
    else:
        print(caminho + ':', 'Deve ser um arquivo ou diretório válido')

if __name__=='__main__':
    main()
