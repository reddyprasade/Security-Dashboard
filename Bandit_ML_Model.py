import mysql.connector
from mysql.connector import Error
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import mlflow.sklearn
from mlflow.tracking import MlflowClient

import os


'''Classifiers'''
#from sklearn.dummy import DummyClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.multiclass import OneVsRestClassifier
from sklearn import svm
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF

'''Metrics/Evaluation'''
from sklearn import metrics
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, roc_curve,recall_score,f1_score,roc_curve,auc,cohen_kappa_score,matthews_corrcoef
from scipy import interp
from itertools import cycle

'''Others'''
from sklearn.model_selection import train_test_split,GridSearchCV
from sklearn.utils.multiclass import unique_labels


pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)


# In[3]:


def data_featching_from_db(table_name):
   """
       Boman.AI Database Connection from Azure Data base with configuration of user name and password and database name
       Parameters:
           table_name: We have to Pass the Table Name to fetech from DB
   """
   try:
       bomandb = mysql.connector.connect(host='boman-db.mysql.database.azure.com',
                                database='boman_dev',
                                user='bomanadmin@boman-db',
                                password='W$&c614isb#kLlFyJJ9gAE8WGH*!$$$boo')
       # SELECT * FROM boman_dev.sast_results where tool_name='Bandit';
       sast_data = "SELECT * FROM boman_dev.{} WHERE tool_name='Bandit';".format(table_name) # I ahve to pass either sast_results or dast_results
       data = pd.read_sql(sast_data,bomandb)
       cursor = bomandb.cursor()
       cursor.execute(sast_data)
       records = cursor.fetchall()

   except Error as e :
       print ("Error connecting MySQL", e)
   finally:
       #closing database connection.
       if(bomandb .is_connected()):
           bomandb.close()
           print("MySQL connection is closed Now")
   return data


# In[4]:


bandit_data = data_featching_from_db('sast_results')
bandit_data.head(2)


# In[5]:


fig, ax = plt.subplots(figsize=(30, 15), subplot_kw=dict(aspect="equal"))

recipe = ["HIGH",
          "LOW",
          "MEDIUM",
          ]

data = bandit_data.vuln_severity.value_counts()

wedges, texts = ax.pie(data, wedgeprops=dict(width=0.5), startangle=-40)

bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
kw = dict(arrowprops=dict(arrowstyle="-"),
          bbox=bbox_props, zorder=0, va="center")

for i, p in enumerate(wedges):
    ang = (p.theta2 - p.theta1)/2. + p.theta1
    y = np.sin(np.deg2rad(ang))
    x = np.cos(np.deg2rad(ang))
    horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
    connectionstyle = "angle,angleA=0,angleB={}".format(ang)
    kw["arrowprops"].update({"connectionstyle": connectionstyle})
    ax.annotate(recipe[i], xy=(x, y), xytext=(1.35*np.sign(x), 1.4*y),
                horizontalalignment=horizontalalignment, **kw)

ax.set_title("Vulnerabilities Severity")
plt.savefig('asserts/vulnerabilities.png',dpi=600)

plt.show()


# In[6]:


len(bandit_data.columns)


# In[7]:


bandit_data.shape


# In[8]:


bandit_data.false_positive.value_counts()


# In[9]:


bandit_data.describe()


# In[10]:


bandit_data.tail()


# In[11]:


df = bandit_data.drop(bandit_data.columns[[2,3,5,6,7,8,10,14,15,16,17,18,19,20,21,22,23,24,25,26]], axis=1)
df.head()


# In[12]:


plt.figure(figsize=(30,15))
sns.countplot(x = df.test_id)


# In[13]:


df.isna().sum()


# In[14]:


df.info()


# In[15]:


df.tail()


# In[16]:


df.isna().sum()


# In[17]:


df.dropna(inplace=True,axis=0)


# In[18]:


df.isna().sum()


# In[19]:


test_id_codes = []
for i in df.test_id:
    test_id_code = int(i[1:])
    d = test_id_codes.append(test_id_code)


# In[20]:


df['test_id_encode'] = test_id_codes


# In[21]:


Num_cols = [x for x in df.columns if df[x].dtypes != 'O']
Cat_cols = [x for x in df.columns if df[x].dtypes == 'O']
print(f'Numerical_columns are :- {Num_cols}')
print('*'*90)
print(f'Categorical_columns are :- {Cat_cols}')  


# In[22]:


df.head()


# In[23]:


plt.figure(figsize=(30,10))
sns.countplot(x = df.vuln_severity)


# In[24]:


plt.figure(figsize=(30,10))
sns.countplot(x = df.vuln_confidence)


# In[25]:


di = {'HIGH':2,
     "MEDIUM":1,
     "LOW":0}

df['vuln_severity'] = df['vuln_severity'].map(di) 
df['vuln_confidence'] = df['vuln_confidence'].map(di)


# In[26]:


def data_featching_from_db(table_name):
    """
        Boman.AI Database Connection from Azure Data base with configuration of user name and password and database name
        Parameters:
            table_name: We have to Pass the Table Name to fetech from DB
    """
    try:
        bomandb = mysql.connector.connect(host='boman-db.mysql.database.azure.com',
                                 database='boman_dev',
                                 user='bomanadmin@boman-db',
                                 password='W$&c614isb#kLlFyJJ9gAE8WGH*!$$$boo')
        # SELECT * FROM boman_dev.sast_results where tool_name='Bandit';
        sast_data = "SELECT * FROM boman_dev.{};".format(table_name) # I ahve to pass either sast_results or dast_results
        data = pd.read_sql(sast_data,bomandb)
        cursor = bomandb.cursor()
        cursor.execute(sast_data)
        records = cursor.fetchall()

    except Error as e :
        print ("Error connecting MySQL", e)
    finally:
        #closing database connection.
        if(bomandb .is_connected()):
            bomandb.close()
            print("MySQL connection is closed Now")
    return data


# In[27]:


apps = data_featching_from_db('app')
apps.head()


# In[28]:


for i in apps.app_type:
    df['app_type'] = i
for j in apps.has_login:
    df['has_login'] = j
for k in apps.database_present:  
    df['database_present'] = k
for l in apps.user_interaction:
    df['user_interaction'] = l


# In[29]:


df.head()


# In[30]:


df.isna().sum()


# In[31]:


def show_hist(x):
    plt.rcParams["figure.figsize"] = 15,18
    x.hist()
show_hist(df)


# In[32]:


def Show_PairPlot(x):
    sns.pairplot(x)
Show_PairPlot(df)
## The Above Code will return this output


# In[33]:


def outlier(x):
    high=0
    q1 = x.quantile(.25)
    q3 = x.quantile(.75)
    iqr = q3-q1
    low = q1-1.5*iqr
    high += q3+1.5*iqr
    outlier = (x.loc[(x < low) | (x > high)])
    return(outlier)
outlier(df['vuln_id']).count()
## The Above Code will return this output


# In[34]:


from scipy.stats import anderson,kstest,shapiro
print('Anderson Darling Test :: ',anderson(df['vuln_id']))
print('='*100)
print('Shapiro Wilk Test :: ',shapiro(df['vuln_id']))
print('='*100) 
print('Kolmogorov–Smirnov Test :: ',kstest(df['vuln_id'],'norm'))
print('='*100)


# In[35]:


show_hist(df)


# In[36]:


li = df.columns
pd.Series(li).to_json("asserts/columns.json")
li


# In[37]:


def create_roc_plot(fpr, tpr):
    """
    Create ROC curve.
    :param fpr: false positive.
    :param tpr: true positive.
    :return: returns a tuple of plt, fig, ax
    """
    fig, ax = plt.subplots(figsize=(30,15))
    plt.plot(fpr, tpr, color='orange', label='ROC')
    plt.plot([0, 1], [0, 1], color='darkblue', linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend()
    plt.show()
    return plt, fig, ax


# In[38]:


def plot_confusion_matrix(y_true, y_pred, classes,
                          normalize=False,
                          title=None,
                          cmap=plt.cm.BuPu):
    """
    This function prints and plots the confusion matrix.
    :param y_true: the actual value of y
    :param y_pred: the predicted value of y
    :param classes: list of label classes to be predicted
    :param normalize: normalize the data
    :param title: title of the plot for confusion matrix
    :param cmap: color of plot
    :return: returns a tuple of plt, fig, ax
    """

    if not title:
        if normalize:
            title = 'Normalized confusion matrix'
        else:
            title = 'Confusion matrix, without normalization'

    # Compute confusion matrix
    cm = metrics.confusion_matrix(y_true, y_pred)
    # Only use the labels that appear in the data
    # li = unique_labels(y_true, y_pred)
    classes =[0,1]
    print(classes)
    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')
    print(cm)

    fig, ax = plt.subplots(figsize=(30,15))
    im = ax.imshow(cm, interpolation='nearest', cmap=cmap)
    ax.figure.colorbar(im, ax=ax)
    # We want to show all ticks...
    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           xticklabels=classes, yticklabels=classes,
           title=title,
           ylabel='True label',
           xlabel='Predicted label')

    # Rotate the tick labels and set their alignment.
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
             rotation_mode="anchor")

    # Loop over data dimensions and create text annotations.
    fmt = '.2f' if normalize else 'd'
    threshold = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], fmt),
                    ha="center", va="center",
                    color="white" if cm[i, j] > threshold else "black")
    fig.tight_layout()
    plt.show()
    return plt, fig, ax


# In[39]:


df.drop('test_id',axis=1,inplace=True)


# In[40]:


df.shape


# In[41]:


def bandit_dataset():
    #path = data_featching_from_db('sast_results')
    #path = "dataset/combined-datasets.csv"
    #with open(path,mode='r') as sql_file:
    #data_reader = pd.read_csv(path)
    data_reader = df.copy()
    print(data_reader.head())
    feature_names = next(data_reader)[:-1]
    data = []
    target = []
    for row in data_reader:
        features = row[:-1]
        label = row[-1]
        data.append([float(num) for num in features])
        target.append(int(label))
    
    data = np.array(data)
    target = np.array(target)
    return Bunch(data=data, target=target, feature_names=feature_names)


# In[42]:


df.head()
X = df.drop('false_positive',axis=1)
y = df.false_positive


# In[43]:



X.head()


# In[44]:


def print_auto_logged_info(r):
    
    #experiment_id = mlflow.create_experiment("DecisionTree")
    #mlflow.delete_experiment(experiment_id)
    tags = {k: v for k, v in r.data.tags.items() if not k.startswith("mlflow.")}
    artifacts = [f.path for f in MlflowClient().list_artifacts(r.info.run_id, "model")]
    # Examine the deleted experiment details.
    #experiment = mlflow.get_experiment(experiment_id)
    #print("Name: {}".format(experiment.name))
    #print("Artifact Location: {}".format(experiment.artifact_location))
    #print("Lifecycle_stage: {}".format(experiment.lifecycle_stage))
    
    print("run_id: {}".format(r.info.run_id))
    print("artifacts: {}".format(artifacts))
    print("params: {}".format(r.data.params))
    print("metrics: {}".format(r.data.metrics))
    print("tags: {}".format(tags))


# In[45]:


class TreeModel:
    """
    DecisionTree classifier to predict binary labels(malignant and benign) of  cancer dataset.
    """

    def __init__(self, **model_params):
        """
        Constructor
        :param model_params: parameters (key-value) for the tree model such as no of estimators, depth of the tree, random_state etc
        """
        self._decision_tree = DecisionTreeClassifier(**model_params)
        self._params = model_params
        #self.data = pd.read_csv("data/bandit.csv")
        #self.data = bandit_dataset()
        #self.data = data_featching_from_db('sast_results')
        
    @classmethod
    def create_instance(cls, **model_params):
        return cls(**model_params)

    @property
    def model(self):
        """
        Getter for the property the model
        :return: return the trained decision tree model
        """

        return self._decision_tree

    @property
    def params(self):
        """
        Getter for the property the model
          :return: return the model params
        """
        return self._params

    def mlflow_run(self, run_name="Boman.AI Classification Run"):
        """
        This method trains, computes metrics, and logs all metrics, parameters,
        and artifacts for the current run
        :param run_name: Name of the experiment as logged by MLflow
        :return: MLflow Tuple (experiment_id, run_id)
        """

        with mlflow.start_run(run_name=run_name) as run:

            # get current run and experiment id
            run_id = run.info.run_uuid
            experiment_id = run.info.experiment_id
            status = run.info.status

            # split the data into train and test
            X_train, X_test, y_train, y_test = train_test_split(X,
                                                                y,
                                                                test_size=0.25,
                                                                random_state=23)

            # train and predict
            self._decision_tree.fit(X_train, y_train)
            y_pred = self._decision_tree.predict(X_test)
            y_probs = self._decision_tree.predict_proba(X_test)

            # Log model and params using the MLflow sklearn APIs
            mlflow.sklearn.log_model(self.model, "Decision-Tree-Classifier")
            mlflow.log_params(self.params)

            acc = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            conf_matrix = confusion_matrix(y_test, y_pred)

            roc = metrics.roc_auc_score(y_test, y_pred)

            # confusion matrix values
            tp = conf_matrix[0][0]
            tn = conf_matrix[1][1]
            fp = conf_matrix[0][1]
            fn = conf_matrix[1][0]

            # get classification metrics
            class_report = classification_report(y_test, y_pred, output_dict=True)
            print(class_report)
            recall_0 = class_report['0']['recall']
            f1_score_0 = class_report['0']['f1-score']
            recall_1 = class_report['1']['recall']
            f1_score_1 = class_report['1']['f1-score']

            # log metrics in mlflow
            mlflow.log_metric("accuracy_score", acc)
            mlflow.log_metric("precision", precision)
            mlflow.log_metric("true_positive", tp)
            mlflow.log_metric("true_negative", tn)
            mlflow.log_metric("false_positive", fp)
            mlflow.log_metric("false_negative", fn)
            mlflow.log_metric("recall_0", recall_0)
            mlflow.log_metric("f1_score_0", f1_score_0)
            mlflow.log_metric("recall_1", recall_1)
            mlflow.log_metric("f1_score_1", f1_score_1)
            mlflow.log_metric("roc", roc)

            # create confusion matrix plot
            plt_cm, fig_cm, ax_cm = plot_confusion_matrix(y_test, y_pred, y_test,
                                                                title="Classification Confusion Matrix")

            temp_name = "confusion-matrix.png"
            fig_cm.savefig(temp_name)
            mlflow.log_artifact(temp_name, "confusion-matrix-plots")
            try:
                os.remove(temp_name)
            except FileNotFoundError as e:
                print(f"{temp_name} file is not found")

            # create roc plot
            plot_file = "roc-auc-plot.png"
            probs = y_probs[:, 1]
            fpr, tpr, thresholds = roc_curve(y_test, probs)
            plt_roc, fig_roc, ax_roc = create_roc_plot(fpr, tpr)
            fig_roc.savefig(plot_file)
            mlflow.log_artifact(plot_file, "roc-auc-plots")
            try:
                os.remove(plot_file)
            except FileNotFoundError as e:
                print(f"{temp_name} file is not found")

            print("<=>" * 40)
            print("Inside MLflow Run with run_id {} and experiment_id {} Status of Machine Leanring Model: {}:".format(run_id,experiment_id,status))
            #print("Max Depth Of Trees:", self.params["get_depth()"])
            print(conf_matrix)
            print(classification_report(y_test, y_pred))
            print("Accuracy Score <=>", acc)
            print("Precision      <=>", precision)
            print("ROC            <=>", roc)

             # fetch the auto logged parameters and metrics for ended run
            return experiment_id, run_id,print_auto_logged_info(mlflow.get_run(run_id=run.info.run_id))


# In[46]:


dtc = TreeModel()


# In[47]:


dtc.mlflow_run()


# In[1]:





# ## Meta Models

# In[48]:


##Preliminary model evaluation using default parameters

#Creating a dict of the models
model_dict = {'MLPClassifier' : MLPClassifier(random_state=3),
              'Stochastic Gradient Descent' : SGDClassifier(random_state=3, loss='log'),
              'Random Forest': RandomForestClassifier(random_state=0),
              'Decision Tree': DecisionTreeClassifier(random_state=0),
              'AdaBoost': AdaBoostClassifier(random_state=3),
              'Gaussian Naive Bayes': GaussianNB(),
              'K Nearest Neighbor': KNeighborsClassifier(5),
              'SVM': svm.SVC(),
              'GPC': GaussianProcessClassifier()}

#Train test split with stratified sampling for evaluation
X_train, X_test, y_train, y_test = train_test_split(X, 
                                                    y, 
                                                    test_size = .25, 
                                                    shuffle = True, 
                                                    stratify = y, 
                                                    random_state = 12345)

#Function to get the scores for each model in a df
def model_score_df(model_dict):   
    model_name, ac_score_list, p_score_list, r_score_list, f1_score_list, kappa_score, MCC = [], [], [],[], [], [], []
    for k,v in model_dict.items():   
        model_name.append(k)
        v.fit(X_train, y_train)
        y_pred = v.predict(X_test)
        ac_score_list.append(accuracy_score(y_test, y_pred))
        p_score_list.append(precision_score(y_test, y_pred, average='macro'))
        r_score_list.append(recall_score(y_test, y_pred, average='macro'))
        f1_score_list.append(f1_score(y_test, y_pred, average='macro'))
        kappa_score.append(cohen_kappa_score(y_test, y_pred))
        MCC.append(matthews_corrcoef(y_test, y_pred))
        cr = classification_report(y_test, y_pred)
        print('='*20,k,"="*20)
        print("Model name is {} Classification Report".format(k.upper()))
        print(cr)
        
        model_comparison_df = pd.DataFrame([model_name, ac_score_list, p_score_list, r_score_list, f1_score_list, kappa_score, MCC]).T
        model_comparison_df.columns = ['model_name', 'accuracy_score', 'precision_score', 'recall_score', 'f1_score', 'kappa_score', 'MCC']
        model_comparison_df = model_comparison_df.sort_values(by='accuracy_score', ascending=False)

    return model_comparison_df

model_score_df(model_dict)# Meta Models


# In[49]:


#Hyperparameter tuning
#Gridsearch with 5-fold cross validation

#RF
bootstrap = [True, False]
criterion = ['gini', 'entropy']
min_samples_split = [2, 5, 10,15]
max_depth = [10, 50, 100, None]
min_samples_leaf = [1, 2, 4, 6]
max_features = ['auto', 'sqrt','log2',None]
max_leaf_nodes = [5,10,20,30]
class_weight = ['balanced', 'balanced_subsample']
n_estimators = [800, 1000, 1500, 2000]
random_state = [3]
#penalty = ['l1','l2'] 
#C = [0.001,0.01,0.1,1]


clf = RandomForestClassifier()
#print(clf.get_params().keys())

params = dict(bootstrap = bootstrap,
              max_depth = max_depth,
              max_features = max_features,
              min_samples_leaf = min_samples_leaf,
              n_estimators = n_estimators,
              random_state=random_state,
              n_jobs = [5],
              criterion= criterion,

              )

gridsearch = GridSearchCV(clf,
                          params, 
                          cv=5,
                          refit=True,
                          return_train_score=True,
                          verbose=1, 
                          n_jobs=-1)

rf_best_model = gridsearch.fit(X, y)
preds = rf_best_model.best_estimator_.predict(X_test)
preds 


# In[50]:


# Define the best models with the selected params from the grdsearch
# Gridsearch was done on a virtual machine outisde of this notebook
# Normally you can just say 'best_model = gridsearch.best_params_' 
# To use the best parameters from the gridsearch

rf_best_model = RandomForestClassifier(bootstrap = True,
                                       max_depth = 50,
                                       max_features = 'auto',
                                       min_samples_leaf = 1,
                                       n_estimators = 1400,
                                       random_state=5)


# In[51]:


rf_best_model.fit(X_train, y_train)
rf_preds = rf_best_model.predict(X_test)


# In[52]:


rf_preds.view()


# In[53]:


model_perfomance = pd.DataFrame()
model_perfomance['Actual'] = y_test
model_perfomance['RFC_Predication'] = rf_preds


# In[54]:


model_perfomance.head()


# In[55]:


#Get the confusion matrix and put it into a df
cm = confusion_matrix(y_test, rf_preds) 

cm_df = pd.DataFrame(cm,
                     index = ['True','False'], 
                     columns = ['True','False'])


# In[56]:


#Plot the confusion Matrix Test set
plt.figure(figsize=(6, 4))

sns.heatmap(cm_df, 
            center=0, 
            cmap=sns.diverging_palette(220, 15, as_cmap=True), 
            annot=True, 
            fmt='g')

plt.title('Random Forest \nF1 Score (avg = macro) : {0:.2f}'.format(f1_score(y_test, rf_preds, average='macro')), fontsize = 13)
plt.ylabel('True label', fontsize = 13)
plt.xlabel('Predicted label', fontsize = 18)
plt.show()

