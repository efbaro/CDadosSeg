import glob
import itertools
from itertools import cycle
import numpy as np
import pandas as pd

import matplotlib.pyplot as plt

from sklearn.preprocessing import label_binarize
from sklearn.multiclass import OneVsRestClassifier

from sklearn.metrics import plot_confusion_matrix as plot_confusion_matrix2
from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_curve, auc
from sklearn.metrics import accuracy_score

from sklearn.model_selection import KFold
from sklearn.model_selection import StratifiedKFold

# Faz treinamento subdividindo os dados
def k_fold_train(clf, df, n_splits=5, clf_name=''):
    """
    Faz o treinamento de n classificadores com dados subdivididos em n pastas,
    e retorna os resultados (Kfold)

    Parameters
    ----------
    clf : object
        Classificador

    df : pandas.core.frame.DataFrame
        DataFrame com os dados

    n_splits : int, opcional
        Número de subdivisões dos dados

    clf_name : str
        Nome do classificador

    Returns
    -------
    list
        lista com as acurácias calculadas em cada pasta (fold)

    list
        lista com os modelos gerados em cada pasta (fold)

    list
        lista com os dados utilizados em cada pasta no formato de tupla (X,y)
    """
    # Separa os dados
    X = df.iloc[:,0:-1].values
    y = df.iloc[:,-1].values

    kf5 = KFold(n_splits=n_splits, shuffle=True, random_state=0)
    #kf5 = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=0)

    scores = []
    models = []
    folds = []

    for train_index, test_index in kf5.split(X):
        X_train_fold = X[train_index]
        y_train_fold = y[train_index]

        X_test_fold = X[test_index]
        y_test_fold = y[test_index]

        clf.fit(X_train_fold, y_train_fold)

        y_pred = clf.predict(X_test_fold)

        # Calcula erro (1-accuracy)
        accuracy = accuracy_score(y_test_fold, y_pred)
        print('Acurácia: {:.3f}'.format(accuracy))

        scores.append(accuracy)
        models.append(clf)
        folds.append((X_train_fold, y_train_fold))

        # Calcula o erro
        erro = 1 - accuracy
        print('Erro: {:.3f}'.format(erro))

         # Imprime a matriz de confusão
        plot_confusion_matrix_(clf,
                           list(np.unique(y_test_fold)),
                           X_test_fold, y_test_fold)

        # Curva ROC
        plot_roc_curve(clf, X_train_fold, y_train_fold, X_test_fold, y_test_fold)

    # Imprime média das acurácias
    print('Média:',sum(scores)/len(scores))

    return scores, models, folds

# Exibe a matriz de confusão
def plot_confusion_matrix_(clf, class_names, X_test, y_test):
    """
    Exibe matriz de confusão normalizada e sem normalização

    Parameters
    ----------
    clf : object
        Classificador

    class_names : list (str)
        Lista com os nomes das classes envolvidas na classificação

    X_test : array or DataFrame
        Conjunto de dados de teste

    y_test : array or DataFrame
        Rótulos dos dados

    """
    titles_options = [("Matriz de confusão, sem normalização", None),
                      ("Matriz de confusão normalizada", 'true')]
    for title, normalize in titles_options:
        disp = plot_confusion_matrix2(clf, X_test, y_test,
                                     display_labels=class_names,
                                     cmap=plt.cm.Blues,
                                     normalize=normalize)
        plt.xticks(rotation=45)
        disp.ax_.set_title(title)

    plt.show()

def plot_roc_k_fold(clf, X, y, n_splits):
    """
    Faz o treinamento de n classificadores com dados subdivididos em n pastas (KFold),
    e exibe uma curva ROC para cada classe com uma linha para cada pasta.

    Parameters
    ----------
    clf : object
        Classificador

    X : array or DataFrame
        Conjunto de dados de treinamento e teste

    y : array or DataFrame
        Rótulos dos dados de treinamento e teste

    n_splits : int
        Número de subdivisões dos dados
    """
    classes = np.unique(y)
    n_classes = len(classes)
    y_bin = label_binarize(y, classes=classes)

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=0)
    classifier = OneVsRestClassifier(clf)
    dic = {'Fold':[], 'Class':[], 'FPR':[], 'TPR':[]}

    for i, (train, test) in enumerate(cv.split(X, y_bin[:,0])):
        classifier.fit(X[train], y_bin[train])
        y_score = classifier.predict_proba(X)

        # Roc por classe
        for i_class in range(n_classes):
            fpr, tpr, _ = roc_curve(y_bin[test,i_class], y_score[test,i_class])
            dic['Fold'] += [i]
            dic['Class'] += [classes[i_class]]
            dic['FPR'] += [fpr]
            dic['TPR'] += [tpr]

    df_result = pd.DataFrame(data=dic)

    # Imprime gráfico
    colors = ['orange', 'red', 'green', 'cyan', 'gold']
    for class_ in list(df_result['Class'].unique()):

        df_plot = df_result[df_result['Class'] == class_]

        tprs = []
        aucs = []
        mean_fpr = np.linspace(0, 1, 100)

        count = 0
        for index, row in df_plot.iterrows():
            fold = row['Fold']
            fpr = row['FPR']
            tpr = row['TPR']
            roc_auc = auc(fpr, tpr)

            plt.plot(fpr, tpr, color=colors[count%len(colors)], lw=1.5,
                     label='ROC fold {0} (AUC = {1:0.3f})' ''.format(
                         fold, roc_auc),alpha=0.5)

            # Guarda pra o cálculo da média
            interp_tpr = np.interp(mean_fpr, fpr, tpr)
            tprs += [interp_tpr]
            aucs += [roc_auc]

            count += 1

        # Calcula as médias
        mean_tpr = np.mean(tprs, axis=0)
        mean_tpr[-1] = 1.0
        mean_auc = auc(mean_fpr, mean_tpr)
        # Calcula desvio padrão
        std_auc = np.std(aucs)
        plt.plot(mean_fpr, mean_tpr, color='blue', lw=1.5,
                     label='Média ROC (AUC = {:0.3f} $\pm$ {:0.3f})' ''.format(
                         mean_auc, std_auc))

        std_tpr = np.std(tprs, axis=0)
        tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
        tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
        plt.fill_between(mean_fpr, tprs_lower, tprs_upper, color='grey',
                         alpha=.2, label=r'$\pm$ 1 desvio padrão')

        plt.plot([0, 1], [0, 1], 'k--', lw=1.5)
        plt.xlim([-0.05, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('Taxa de Falso Positivo')
        plt.ylabel('Taxa de Verdadeiro Positivo')
        plt.title('Curva ROC \n (Classe='+class_+')')
        plt.legend(loc="lower right")
        plt.show()

# Exibe curva ROC
def plot_roc_curve(clf, X_train, y_train, X_test, y_test):
    """
    Exibe a curva roc fazendo o treinamento considerando as classes um contra todos

    Parameters
    ----------
    clf : object
        Classificador

    X_train : array or DataFrame
        Conjunto de dados de treinamento

    y_trian : array or DataFrame
        Rótulos dos dados de treinamento

    X_test : array or DataFrame
        Conjunto de dados de teste

    y_test : array or DataFrame
        Rótulos dos dados de teste

    """
    # Obtém os nomes das classes
    classes = np.unique(y_test)
    n_classes = len(classes)
    # Binariza os rótulos
    y_train_bin = label_binarize(y_train, classes=classes)
    y_test_bin = label_binarize(y_test, classes=classes)

    # Cria o modelo um contra todos
    classifier = OneVsRestClassifier(clf)
    # Treina o modelo
    classifier.fit(X_train, y_train)
    # Faz predição com probabilidades sobre os dados de teste
    y_score = classifier.predict_proba(X_test)

    # Plotting and estimation of FPR, TPR
    fpr = dict()
    tpr = dict()
    roc_auc = dict()
    for i in range(n_classes):
        fpr[i], tpr[i], _ = roc_curve(y_test_bin[:, i], y_score[:, i])
        roc_auc[i] = auc(fpr[i], tpr[i])
    #
    colors = cycle(['blue', 'red', 'green', 'cyan', 'gold'])
    for i, color in zip(range(n_classes), colors):
        plt.plot(fpr[i], tpr[i], color=color, lw=1.5,
                 label='ROC curve of class {0} (area = {1:0.3f})' ''.format(
                     classes[i], roc_auc[i]))

    plt.plot([0, 1], [0, 1], 'k-', lw=1.5)
    plt.xlim([-0.05, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver operating characteristic for multi-class data')
    plt.legend(loc="lower right")
    plt.show()

# Exibe a matriz de confusão
def plot_confusion_matrix(y, y_pred, classes, title='Matriz de confusão', cmap=plt.cm.Blues):
    """
    Exibe matriz de confusão sem normalização

    Parameters
    ----------
    y : array or DataFrame
        Array com rótulos verdadeiros dos dados
    y_pred : array or DataFrame
        Array com rótulos preditos dos dados
    classes : set
        Conjunto de classes relacionadas aos dados
    title : str, opcional
        Título da matriz de confusão
    cmap : matplotlib.colors.LinearSegmentedColormap, opcional
        Grade de cores a ser aplicado na matriz de confusão
    """
    cm=confusion_matrix(y, y_pred)
    plt.imshow(cm, interpolation = 'nearest',cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation = 45)
    plt.yticks(tick_marks, classes)

    thresh = cm.max()/2
    for i, j in itertools.product(range(cm.shape[0]),range(cm.shape[1])):
        plt.text(j, i, cm[i,j], horizontalalignment="center", color="white" if cm[i,j]>thresh else "black")

    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')

# Exibe a distribuição de classes dos dados
def plot_distribuicao_classes(df, class_col_name, figsize=(7,5), color='red'):
    """
    Mostra a distribuição dos dados em gráfico de barras

    Parameters
    ----------
    df : pandas.core.frame.DataFrame
        DataFrame com os dados

    class_col_name : str
        Nome da coluna em que os rótulos serão contados

    figsize : tuple (int, int)
        Comprimento e altura do gráfico

    color : str
        Cor das barras do gráfico
    """
    labels = df[class_col_name].value_counts().keys()
    values = df[class_col_name].value_counts().tolist()

    fig = plt.figure(figsize=figsize)

    plt.bar(labels, values, color=color)

    plt.xlabel('Classes')
    plt.ylabel('Qtd. de exemplos')
    plt.xticks(rotation=45)
    plt.title('Distribuição de classes')
    plt.show()

def plot_resultados(x, x_label, y, y_label, divisao, titulo, figsize=(7,5)):
    """
    Imprime gráfico de linhas

    Parameters
    ----------
    x : list
        lista com os dados do eixo X
    x_label : str
        rótulo do eixo x
    y : list
        lista com os dados do eixo y
    y_label : str
        rótulo do eixo y
    divisao : list
        lista com elementos que permitem dividir os dados de x e y
    titulo : str
        Título do gráfico
    figsize : tuple, opcional
        Tamanho do gráfico, tupla com altura e largura (largura, altura)

    """
    x = np.array(x)
    y = np.array(y)
    divisao = np.array(divisao)
    fig = plt.figure(figsize=figsize)
    for label in np.unique(divisao):
        index = np.where(divisao == label)
        plt.plot(x[index], y[index], 'o-', label=label)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.title(titulo)
    plt.legend()
    plt.show()

def get_csv_files(path):
    """
    Retorna uma lista com caminho e nome de todos os arquivos CSVs em um determinado caminho.

    Parameters
    ----------
    path : str
        Caminho para pasta onde estão os arquivos.

    Returns
    -------
    list
        Lista com o caminho e nome de todos os arquivos CSV contidos
        no caminho passado como parâmetro.
    """
    return glob.glob(path + '/**/*.csv', recursive=True)
