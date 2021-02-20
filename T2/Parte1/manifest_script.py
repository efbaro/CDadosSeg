"""
    Autor: Everton Fernando Baro
    Data: 17/02/2021
"""
import sys
import os
import xml.dom.minidom as md
import argparse

def get_apks(path):
    """
    Retorna uma lista com caminho e nome de todos os arquivos APK.

    Parameters
    ----------
    path : str
        Caminho para pasta onde estão os arquivos APK.

    Returns
    -------
    list
        Lista com o caminho e nome de todos os arquivos APK contidos
        no caminho passado como parâmetro.
    """

    files = []

    list_dir = os.listdir(path)
    # Percorre lista de diretórios e arquivos
    for d in list_dir:
        # Verifica se é arquivo
        if os.path.isfile(path + '/' + d):
            # Verifica se o arquivo é to tipo apk
            if d.endswith('.' + 'apk'):
                # Armazena na lista de arquvios, armazena já com o caminho
                files.append(path + '/' + d)

    return files


def extract_manifest(path_apks, path_out):
    """
    Extrai AndroidManifest.xml dos APKs contidos na pasta "path_apks"
    e os salva na pasta "path_out".

    Parameters
    ----------
    path_apks : str
        Caminho para a pasta onde estão contidos os APKs.
    path_out : str
        Camingo onde serão salvos os arquivos XMLs.
    """
    # Busca todos os arquivos com extensão APK no diretório path_apks
    files = get_apks(path_apks)
    # Cria pasta para armazenar os AndroidManifests
    os.system('mkdir ' + path_out)

    for file in files:
        # Executa a extração e salva (pasta com o mesmo nome do arquivo com final ".out")
        os.system('java -jar apktool_2.5.0.jar -q d -s \''  + file + '\' -o \'' + file + '.out\'')
        # Divide nome do APK para obter o nome e a versão da aplicação
        splits = file.split('/')[-1]
        splits = splits.split('_')
        package_name = splits[0] # Nome do pacote da aplicação
        version = splits[1] # versão da aplicação
        # Move o AndroidManifest.xml que foi extraido para pasta da variável path_out
        os.system('mv \''+ file +'.out/AndroidManifest.xml\' '+ path_out + '/AndroidManifest_'+package_name+'_'+version+'_.xml' )
        # Remove pasta onde foi extraido os dados
        os.system('rm -rf \'' + file + '.out\'')


def get_xml_files(path):
    """
    Retorna uma lista com caminho e nome de todos os arquivos XML.

    Parameters
    ----------
    path : str
        Caminho para pasta onde estão os arquivos XML.

    Returns
    -------
    list
        Lista com o caminho e nome de todos os arquivos XML contidos
        no caminho passado como parâmetro.
    """

    files = []

    list_dir = os.listdir(path)
    # Percorre lista de diretórios e arquivos
    for d in list_dir:
        # Verifica se é arquivo
        if os.path.isfile(path + '/' + d):
            # Verifica se o arquivo é to tipo xml
            if d.endswith('.' + 'xml'):
                # Armazena na lista de arquvios, armazena já com o caminho
                files.append(path + '/' + d)

    return files


def get_permissions(path_xmls):
    """
    Retorna um dicionário em que a chave é o pacote e a versão da aplicação
    e o valor é uma lista com as permissões da aplicação.

    Parameters
    ----------
    path_xmls : str
        Caminho para pasta onde estão os arquivos XMLs (AndroidManifest).

    Returns
    -------
    dict
        Dicionário com as permissões de cada um dos APKs (chave: pacote e versão,
        valor: lista com permissões).
    """
    files = get_xml_files(path_xmls)

    dic = {}

    for file in files:
        # Extrai nome do pacote e versão da aplicação
        split_file = file.split('_')
        package_name = split_file[1]
        version = split_file[2]
        app_name = package_name + '_v' + version

        doc = md.parse(file)
        uses_permissions = doc.getElementsByTagName('uses-permission')

        # Utiliza o dicionário para remover repetições de permissões
        dic_permissions = {}
        for permission in uses_permissions:
            name = permission.getAttribute("android:name")
            dic_permissions[name.split('.')[-1]] = 1

        list_permissions = list(dic_permissions.keys())
        list_permissions.sort()
        dic[app_name] = list_permissions

    return dic


def get_interseccao_permissoes(dic):
    """
    Retorna lista com as permissões que são comuns a
    todas as aplicações

    Parameters
    ----------
    dic : dict
        Dicionário em que a chave é o nome da aplicação, e o valor
        é a lista de permissões.

    Returns
    -------
    list
        lista com as permissões que são comuns a todas as aplicações
    """
    d = list(dic.values())
    comuns = set(d[0]).intersection(*d)
    comuns = list(comuns)
    comuns.sort()
    return comuns


def get_lista_permissoes_unicas(dic):
    """
    Retorna lista que as permissões e ocorrem em somente uma aplicação

    Parameters
    ----------
    dic : dict
        Dicionário em que a chave é o nome da aplicação, e o valor
        é a lista de permissões.

    Returns
    -------
    list
        lista com as permissões e ocorrem em somente uma aplicação
    """
    # Conta para cada permissão a quantidade do ocorrências
    dic_count = {}
    for key, values in dic.items():
        for value in values:
            if value in dic_count.keys():
                dic_count[value] += 1
            else:
                dic_count[value] = 1

    # Adiciona a lista as permissões que ocorreram somente uma vez
    permissoes_unicas = []
    for key, value in dic_count.items():
        if value == 1:
            permissoes_unicas.append(key)

    return permissoes_unicas


def get_dicionario_app_permissoes_unicas(dic):
    """
    Retorna um dicionário em que a chave é o pacote e a versão da aplicação
    e o valor é uma lista com as permissões que somente ocorrem naquela aplicação.

    Parameters
    ----------
    dic : dict
        Dicionário em que a chave é o nome da aplicação, e o valor
        é a lista de permissões.

    Returns
    -------
    dict
        Dicionário em que a chave é o pacote e a versão da aplicação
        e o valor é uma lista com as permissões que somente ocorrem naquela aplicação.
    """
    permissoes_unica = get_lista_permissoes_unicas(dic)

    dic_out = {}
    for key, value in dic.items():
        dic_out[key] = []
        for unique_value in permissoes_unica:
            if unique_value in value:
                dic_out[key].append(unique_value)

    return dic_out


def imprime_permissoes(dic, titulo):
    """
    Imprime todas as permissões do dicionário

    Parameters
    ----------
    dic : dict
        Dicionário em que a chave é o nome da aplicação, e o valor
        é a lista de permissões.
    """
    print('='*20)
    print(titulo)
    print('='*20)

    for key, value in dic.items():
        print(key+':',value,'\n')

def imprime_permissoes_comuns(permissoes):
    """
    Imprime as permissões que são comuns a
    todas as aplicações

    Parameters
    ----------
    permissoes : list
        Lista com as permissões que são comuns a todas as aplicações
    """
    print('='*20)
    print('Permissões comuns das APKs')
    print('='*20)
    print(permissoes)


def main():
    """
    Inicia a execução do programa
    """

    parser = argparse.ArgumentParser(description='Análise de APKs.')
    parser.add_argument('-e', '--extract', action='store_true', help='Extrai ' + \
                        'AndroidManifest.xml das APKs do diretório passado como ' + \
                        'argumento para o diretório manifests (criado ' + \
                        'automaticamente pelo script).')
    parser.add_argument('diretorio', type=str, help='Diretório com arquivos ' + \
                        'AndroidManifest.xml, ou com arquivos APKs caso o ' + \
                        'argumento -e seja usado.')
    args = parser.parse_args()

    manifests_dir = ''

    try:
        if args.extract:
            manifests_dir = 'manifests'
            # Extrai AndroidManifest das APKs e armazena na pasta manifests
            extract_manifest(args.diretorio, manifests_dir)
        else:
            manifests_dir = args.diretorio

        dic = get_permissions(manifests_dir)

        if len(dic) != 0:
            imprime_permissoes(dic, 'Permissões por APK')

            dic_permissoes_unicas = get_dicionario_app_permissoes_unicas(dic)
            imprime_permissoes(dic_permissoes_unicas, 'Permissões únicas por APK')

            lista_permissoes_comuns = get_interseccao_permissoes(dic)
            imprime_permissoes_comuns(lista_permissoes_comuns)
        else:
            print('Não há arquivos XML no diretório', manifests_dir)

    except IOError:
        print(args.diretorio, ': Arquivo ou diretório inexistente')


if __name__=='__main__':
    main()
