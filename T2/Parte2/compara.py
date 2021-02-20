"""
    Autor: Everton Fernando Baro
    Data: 18/02/2021
"""
import sys
import os
import pefile
import argparse

def get_dic_secoes(pfile):
    """
    Retorna um dicionário em que a chave é o nome da seção e o valor
    é uma lista com as permissões referentes ao binário passado como
    parâmetro (pfile)

    Parameters
    ----------
    pfile : pefile object

    Returns
    -------
    dict
        Dicionário em que a chave é o nome da seção e o valor
        é uma lista com as permissões
    """
    dic = {}
    for i in range(len(pfile.sections)):
        nome_secao = pfile.sections[i].Name.decode('utf-8')
        nome_secao = nome_secao.replace('\x00','')
        permissoes = [pfile.sections[i].IMAGE_SCN_MEM_READ,
                      pfile.sections[i].IMAGE_SCN_MEM_WRITE,
                      pfile.sections[i].IMAGE_SCN_MEM_EXECUTE]
        dic[nome_secao] = permissoes

    return dic

def get_valores_comuns(lista1, lista2):
    """
    Retorna uma lista com os valores comuns as duas listas

    Parameters
    ----------
    lista1 : list
        lista com valores para intersecção

    lista2 : list
        lista com valores para intersecção

    Returns
    -------
    list
        Lista com os valores comuns as duas listas
    """
    d = list([lista1, lista2])
    comuns = set(d[0]).intersection(*d)
    return comuns


def imprimir_secoes_comuns(dic_pe1, nome_arquivo1, dic_pe2,  nome_arquivo2):
    """
    Imprime as seções que são comuns aos dois binários

    Parameters
    ----------
    dic_pe1 : dict
        Dicionário em que a chave é o nome da seção e o valor
        é uma lista com as permissões

    nome_arquivo1 : str
        Nome do arquivo binário que deu origem aos dados do dicionário dic_pe1

    dic_pe2 : dict
        Dicionário em que a chave é o nome da seção e o valor
        é uma lista com as permissões

    nome_arquivo2 : str
        Nome do arquivo binário que deu origem aos dados do dicionário dic_pe2
    """

    # Busca as seções comunus aos dois arquivos (por meio do dicionário)
    secoes_comuns = get_valores_comuns(list(dic_pe1.keys()), list(dic_pe2.keys()))

    # Imprime o cabeçalho
    print("Seções comuns aos dois binários")
    print('{:<15.15} {:<25.25}   {:<25.25}'.format('Nome da Seção', nome_arquivo1, nome_arquivo2))
    # Percorre as seções que são comuns aos dois arquivos
    for secao in secoes_comuns:

        # Obtém as permissões da seção de cada arquivo
        permissoes_pe1 = dic_pe1[secao]
        permissoes_pe2 = dic_pe2[secao]

        str_permissoes_pe1 = ['-','-','-']
        str_permissoes_pe2 = ['-','-','-']
        str_permissoes_aux = ['r','w','x']

        # Codifica as permissões dos arquivos para o formato [rwx]
        for i in range(len(permissoes_pe1)):
            if permissoes_pe1[i]:
                str_permissoes_pe1[i] = str_permissoes_aux[i]
            if permissoes_pe2[i]:
                str_permissoes_pe2[i] = str_permissoes_aux[i]

        # Concatena a lista de permissões em uma única string
        str_permissoes_pe1 = ''.join(str_permissoes_pe1)
        str_permissoes_pe2 = ''.join(str_permissoes_pe2)

        # Verifica se as seções são executáveis ou não
        str_executavel_pe1 = permissoes_pe1[2] and 'executável' or 'não executável'
        str_executavel_pe2 = permissoes_pe2[2] and 'executável' or 'não executável'

        # Imprime as informações sobre a seção de maneira formatada
        print('{:<15.15} {:<3} {:>21.21}   {:<3} {:>21.21}'.format(secao, str_permissoes_pe1,
                                                                str_executavel_pe1,
                                                                str_permissoes_pe2,
                                                                str_executavel_pe2))

    print()

def get_valores_unicos(lista1, lista2):
    """
    Retorna uma lista com os valores únicos da primeira lista (lista1)

    Parameters
    ----------
    lista1 : list
        lista com valores da primira lista

    lista2 : list
        lista com valores da segunda lista

    Returns
    -------
    list
        Lista com os valores únicos da primeira lista
    """
    # Obtém os valores comuns as duas listas
    comuns = get_valores_comuns(lista1, lista2)
    # Obtém os valores únicos da lista 1
    unicos = list(set(lista1) - set(comuns))

    return unicos

def imprimir_secoes_unicas(dic_pe, nome_arquivo, secoes_unicas):
    """
    Imprime de maneira formatada as seções únicas do binário PE

    Parameters
    ----------
    dic_pe : dict
        Dicionário em que a chave é o nome da seção e o valor
        é uma lista com as permissões

    nome_arquivo : str
        Nome do arquivo binário que deu origem aos dados do dicionário dic_pe

    secoes_unicas : list
        Lista com o nome das seções que ocorrem unicamente no binário PE
    """

    print('Seções presentes apenas no arquivo', nome_arquivo)
    print('{:<15} {:>19}'.format('Nome da Seção', 'Permissões'))

    for secao in secoes_unicas:

        permissoes = dic_pe[secao]

        str_permissoes = ['-','-','-']
        str_permissoes_aux = ['r','w','x']
        for i in range(len(permissoes)):
            if permissoes[i]:
                str_permissoes[i] = str_permissoes_aux[i]

        str_permissoes = ''.join(str_permissoes)
        str_executavel = permissoes[2] and 'executável' or 'não executável'

        print('{:<15.15} {:>15} {:<3}'.format(secao, str_executavel, str_permissoes))

    print()


def imprimir(pe1, nome_arquivo1, pe2,  nome_arquivo2):
    """
    Imprimindo na saída padrão quais seções são comuns a ambos os binários e
    quais somente estão presentes no binário 1 e quais somente estão presentes
    no binário 2.

    Parameters
    ----------
    pe1 : object (PE)
        Objeto do tipo PE (A Portable Executable representation.)

    nome_arquivo1 : str
        Nome do arquivo de origem do objeto pe1.

    pe2 : object (PE)
        Objeto do tipo PE (A Portable Executable representation.)

    nome_arquivo2 : str
        Nome do arquivo de origem do objeto pe2.
    """

    # Obtém seções e permissões dos arquivos
    dic_pe1 = get_dic_secoes(pe1)
    dic_pe2 = get_dic_secoes(pe2)

    # Imprime as seções comuns aos dois binários
    imprimir_secoes_comuns(dic_pe1, nome_arquivo1, dic_pe2,  nome_arquivo2)

    # Obtém as seções que são únicas a cada binário
    secoes_unicas_pe1 = get_valores_unicos(list(dic_pe1.keys()), list(dic_pe2.keys()))
    secoes_unicas_pe2 = get_valores_unicos(list(dic_pe2.keys()), list(dic_pe1.keys()))

    # Imprime as seções únicas de cada binário
    imprimir_secoes_unicas(dic_pe1, nome_arquivo1, secoes_unicas_pe1)
    imprimir_secoes_unicas(dic_pe2, nome_arquivo2, secoes_unicas_pe2)

def main():
    """
    Inicia a execução do programa
    """

    parser = argparse.ArgumentParser(description='Análise de binários Portable Executable (PE).')
    parser.add_argument('arquivo_1', type=str, help='Arquivo binário do tipo PE.')
    parser.add_argument('arquivo_2', type=str, help='Arquivo binário do tipo PE.')

    args = parser.parse_args()

    arquivo1 = args.arquivo_1
    arquivo2 = args.arquivo_2

    # Verifica se arquivo ou diretório existe
    if os.path.exists(arquivo1) and os.path.exists(arquivo2):
        # Verifica se o caminho é um arquivo
        if os.path.isfile(arquivo1) and os.path.isfile(arquivo2):
            try:
                pe1 = pefile.PE(arquivo1)
                pe2 = pefile.PE(arquivo2)

                # Remove o caminho do nome do arquivo
                nome_arquivo1 = arquivo1.split('/')[-1]
                nome_arquivo2 = arquivo2.split('/')[-1]

                # Imprimir resultados na saída padrão
                imprimir(pe1, nome_arquivo1, pe2, nome_arquivo2)
            except pefile.PEFormatError:
                print('Pelo menos um dos arquivos não é um arquivo binário do tipo '+ \
                      'Portable Executable (PE).')
                sys.exit(1)
        else:
            print('Pelo menos um dos parâmetros não é um arquivo.')
            sys.exit(2)
    else:
        print('Pelo menos um dos parâmetros não é um arquivo existente.')
        sys.exit(3)


if __name__=='__main__':
    main()
