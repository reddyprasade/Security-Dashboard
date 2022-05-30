# Code source: https://dash-bootstrap-components.opensource.faculty.ai/examples/simple-sidebar/
from zlib import DEF_BUF_SIZE
import dash
import dash_bootstrap_components as dbc
import dash_html_components as html
import dash_core_components as dcc
from matplotlib.pyplot import figure
import plotly.express as px
from dash.dependencies import Input, Output
import pandas as pd
import mysql.connector
from mysql.connector import Error

import plotly.graph_objects as go
import warnings
warnings.filterwarnings("ignore")


def etl(table_name):
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
def data_featching_from_db(table_name,tn):
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
       sast_data = "SELECT * FROM boman_dev.{} WHERE tool_name='{}';".format(table_name,tn) # I ahve to pass either sast_results or dast_results
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

# Tools info
print('*'*30,'ALL APPLICATION SECURITY TOOLS ','*'*30)
sast_tn = etl('sast_results')
dast_tn = etl('dast_results')
sca_tn = etl('sca_results')
sc_tn = etl('secret_scan_results')
tool_master = etl('tool_master')
app_data = etl('app')

vuln_name_count = sast_tn.vuln_name.value_counts()
# Vulnerabilities Severity
vuln_severity_count = sast_tn.vuln_severity.value_counts()
vuln_created_date = sast_tn.created_at.value_counts()

# DAST TOOLS
print('*'*30,'DAST TOOLS','*'*30)
df_zap = data_featching_from_db('dast_results','OWASP Zap')
#df_nodejs = data_featching_from_db('')


# ToKen Count
# select count(1) from boman_dev.sast_results;(SQL)
sast_count = sast_tn.scan_token.count()   
dast_count = dast_tn.scan_token.count()
sc_count = sc_tn.scan_token.count()
sca_count = sca_tn.scan_token.count()

# Overall Scan Tools
total_scan = {'Security Scanning Tools Names':['SAST','DAST','Secret Scan','SCA'],
        'Count of Each Scan Tools':[sast_count,dast_count,sc_count,sca_count]}
total_scan_count = sum(total_scan['Count of Each Scan Tools'])

# SAST tools Count
sast_di = sast_tn.tool_name.value_counts()
sast_tool_name_count = {'Tool Name':sast_di.keys(),'Tool Count':sast_di.values}

# DAST tools Count
dast_tools_names = dast_tn.tool_name.value_counts()
dast_tool_name_count = {'Tool Name':dast_tools_names.keys(),'Tool Count':dast_tools_names.values}

# SCA tools 
sca_tools_names = sca_tn.tool_name.value_counts()
sca_tool_name_count = {'Tool Name':sca_tools_names.keys(),'Tool Count':sca_tools_names.values}

# SC Tools
sc_tool_names = sc_tn.tool_name.value_counts()
sc_tool_names_count = {'Tool Name':sc_tool_names.keys(),'Tool Count':sc_tool_names.values}

# Total Sast Vulnerabilities Names
sast_vuln_name = sast_tn.vuln_name.value_counts()
sast_vuln_name_count ={'Total Vulnerabilities Names':sast_vuln_name.keys()[0:15],
                "Count Each Vulnerabilities":sast_vuln_name.values[0:15]
                }
# Total dast Vulnerabilities Names
dast_vuln_name = dast_tn.vuln_name.value_counts()
dast_vuln_name_count ={'Total Vulnerabilities Names':dast_vuln_name.keys()[0:15],
                "Count Each Vulnerabilities":dast_vuln_name.values[0:15]
                }
# Total SCA Vulnerabilities Names
sca_vuln_name = sca_tn.vuln_name.value_counts()
sca_vuln_name_count ={'Total Vulnerabilities Names':sca_vuln_name.keys()[0:15],
                "Count Each Vulnerabilities":sca_vuln_name.values[0:15]
                }
# Total SS Vulnerabilities Names
ss_vuln_name = sc_tn.vuln_name.value_counts()
ss_vuln_name_count ={'Total Vulnerabilities Names':ss_vuln_name.keys()[0:15],
                "Count Each Vulnerabilities":ss_vuln_name.values[0:15]
                }

# Machine Learning Model Preicated False Positive
sast_tool_fp = sast_tn.false_positive.value_counts()
dast_tool_fp = dast_tn.false_positive.value_counts()
sast_fp_0=sast_tool_fp[0.0],
dast_fp_0 = dast_tool_fp[0.0]
total_false_postive = {'False Postive and Negative Found':["False Positive-1",'False Nagative-0'],
                "Count False Postive and Negative":[sast_tool_fp[1.0], sum(sast_fp_0,dast_fp_0)]
                }
# SAST TOOLS
print('*'*30,'SAST TOOLS','*'*30)

# Bandit tool
print('*'*30,'SAST BANDIT(PYTHON) TOOLS','*'*30)
df_bandit = data_featching_from_db('sast_results','Bandit')

# Brakeman
print('*'*30,'SAST Brakeman TOOLS','*'*30)
#df_brakeman= data_featching_from_db('sast_results','Brakeman')

# PHP
print('*'*30,'SAST PHP Code Sniffer TOOLS','*'*30)
#df_php  =data_featching_from_db('sast_results','PHP Code Sniffer')


# DAST TOOlS
print('*'*30,'DAST TOOLS','*'*30)
#df_zap = etl('dast_tn')

#external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.UNITED]) #dbc.themes.UNITED
app.title = "Boman.ai Dashboard"

# styling the sidebar
SIDEBAR_STYLE = {
    "position": "fixed",
    "top": 0,
    "left": 0,
    "bottom": 0,
    "width": "18rem",
    "padding": "2rem 1rem",
    "background-color": "#f2faf9",
}

# padding for the page content
CONTENT_STYLE = {
    "margin-left": "18rem",
    "margin-right": "2rem",
    "padding": "2rem 1rem",
}

sidebar = html.Div(
    [
        html.H2("Boman.AI", className="display-4"),
        #html.Img(src = 'https://static.wixstatic.com/media/a3de5f_9a5db212e88d49a891fa21f99c863d6c~mv2.png/v1/fill/w_381,h_206,al_c,usm_0.66_1.00_0.01,enc_auto/a3de5f_9a5db212e88d49a891fa21f99c863d6c~mv2.png'),
        html.Hr(),
        html.P(
            "DevOpsSec Application Security powered by AI/ML", className="lead"
        ),
        dbc.Nav(
            [
                dbc.NavLink("Home", href="/", active="exact"),

                dbc.DropdownMenu(
                        label="Data Dashboard",
                        nav=True,
                        children=[
                                dbc.DropdownMenuItem("Bandit Data", href="/badnitdata", active="exact"),
                                dbc.DropdownMenuItem("Brakeman Data", href="/brakemandata", active="exact"),
                                dbc.DropdownMenuItem("Zap Data", href="/zapdata", active="exact"),
                                dbc.DropdownMenuItem('PHP', href="/phpdata", active="exact"),
                                dbc.DropdownMenuItem('NodeJs', href="/nodejs",active='exact'),
                                dbc.DropdownMenuItem('Semgrep', href="/semgrep",active='exact')
                        ]),
                dbc.NavItem(dbc.NavLink("Model", href="/model", active="exact")),
                dbc.NavItem(dbc.NavLink("Time Series", href="/time", active="exact")),
                #dbc.NavItem(dbc.NavLink("Personlization", href="/personlization", active="exact")),
            ],
            vertical=True,
            pills=True,
        ),
    ],
    style=SIDEBAR_STYLE,
)
content = html.Div(id="page-content", children=[], style=CONTENT_STYLE)
app.layout = html.Div([
        dcc.Location(id="url"),sidebar,content,])

@app.callback(
    Output("page-content", "children"),
    [Input("url", "pathname")]
)

def render_page_content(pathname):
    if pathname == "/":
        tool_master_data=[      html.H1('Boman.ai Analysis Dashboard',style={'textAlign':'center'}),
                                # Over all Scan Tools
                                
                                html.P("Overall Different Application Security Testing  Tools Which we are Listed in Below: "),
                                html.Li("This are the Top Used Security Scaners by the Customers"),
                                html.Li('Total Number of Scan Done across all the Security Scanning Tools: {}'.format(total_scan_count)),
                                
                                html.Li("Total Scan done in SAST is :...............  {}".format(sast_count)),
                                html.Li("Total Scan done in DAST is :...............  {}".format(dast_count)),
                                html.Li("Total Scan done in SCA is :................  {}".format(sca_count)),
                                html.Li("Total Scan Done in Secret Scan is :......  {}".format(sc_count)),

                                # Total Overall Security Scan Count 
                                dcc.Graph(id='Security_Scanning_Tools_bar',
                                        # Total Number of Scan Done In Overall From (SAST, DAST, SC, SCA) - Code Review tools.(X – Tool  Name and Y – No Count) 
                                        figure = px.bar(total_scan,
                                                x='Security Scanning Tools Names',
                                                y='Count of Each Scan Tools',
                                                text_auto='.2s',
                                                title='Total Number of Scan Done From (SAST, DAST, SC, SCA)',
                                                labels={'x':"Security Scanning Tools Names",'y':'Count of Each Scan Tools'}),
                                        config= {'displaylogo': False}
                                ),
                                # SAST Scan Tools
                                dcc.Graph(id ='Tool_name_barchart',
                                        figure= px.bar(sast_tool_name_count, x='Tool Name',y='Tool Count',
                                                text_auto='.2s',title='All SAST Scan Tool',labels={'x':"Tools Names ",'y':'Count of Each Scan Tools'}),
                                        config= {'displaylogo': False}
                                ),
                                # DAST Scan Tools
                                dcc.Graph(id ='Tool_name_barchart',
                                        figure= px.bar(dast_tool_name_count, x='Tool Name',y='Tool Count',
                                                text_auto='.2s',title='All DAST Scan Type',
                                                color_discrete_sequence = px.colors.sequential.Plasma,
                                                labels={'x':"Tools Names Type ",'y':'Count of Each Scan Tools'}
                                                ),
                                        config= {'displaylogo': False}
                                ),
                                # SCA Scan Tools 
                                dcc.Graph(id = "customer_master_barchart",
                                        figure= px.bar(sca_tool_name_count, 
                                                        x='Tool Name',
                                                        y='Tool Count',
                                                        text_auto='.2s',
                                                        title='All SCA Scan',
                                                        labels={'x':"Total Names",'y':'Tool Count '},
                                                        color_discrete_sequence = px.colors.sequential.Cividis
                                                        ),
                                        config= {'displaylogo': False}
                                ),
                                # SC Scan Tools 
                                dcc.Graph(id = "sc",
                                        figure= px.pie(sc_tool_names_count, 
                                        names = 'Tool Name',
                                        values = 'Tool Count',
                                        #text_auto='.2s',
                                        title='All Secret Scanning Tools',
                                        hole=.5,
                                        color_discrete_sequence = px.colors.sequential.Darkmint,
                                        labels={'x':"Total Names",'y':'Tool Count '}),
                                        config= {'displaylogo': False}
                                ),
                                html.P("Total No of False Postive is {}".format(sum(total_false_postive['Count False Postive and Negative']))),
                                html.P("Total No Of False Postive are Removed {}".format(total_false_postive['Count False Postive and Negative'][1])),
                                dcc.Graph(id='false_postive_bar',
                                        # false positive vulnerability in  application (1)
                                        # false nagative no vulnerability in application (0)
                                        #figure = px.bar(total_false_postive, x='False Postive and Negative Found',y = 'Count False Postive and Negative',text_auto='.2s',title='Total Vulnerabilities in SAST & DAST Predicate by Machine Learning Model'),
                                        config= {'displaylogo': False},
                                        figure = px.pie(total_false_postive, 
                                                names='False Postive and Negative Found',
                                                hole=.7,
                                                color_discrete_sequence=px.colors.sequential.Sunsetdark,
                                                values = 'Count False Postive and Negative', 
                                                title='Total Vulnerabilities in SAST DAST Predicate by Machine Learning Model')
                                ),
                                dcc.Graph(id='Sast_vuln_names',
                                        figure= px.pie(sast_vuln_name_count, names='Total Vulnerabilities Names',values='Count Each Vulnerabilities',
                                                        #text_auto='.2s',
                                                        hole=.1,
                                                        color_discrete_sequence=px.colors.sequential.Plasma,
                                                        title='Top 15 Vulnerabilities in SAST',
                                                        labels={'x':"Total Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                  ),
                                dcc.Graph(id='dast_vuln_names',
                                        figure= px.bar(dast_vuln_name_count, x='Total Vulnerabilities Names',y='Count Each Vulnerabilities',
                                                        text_auto='.2s', 
                                                        color_discrete_sequence=px.colors.sequential.RdBu,
                                                        title='Top 15 Vulnerabilities in DAST'),
                                                        #labels={'x':"Total Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                ),
                                dcc.Graph(id='sca_vuln_names',
                                        figure= px.pie(sca_vuln_name_count, names='Total Vulnerabilities Names',values='Count Each Vulnerabilities',
                                                        #text_auto='.2s',
                                                        hole=.3,
                                                        color_discrete_sequence=px.colors.sequential.Rainbow,
                                                        title='Top 15 Vulnerabilities in SCA',
                                                        labels={'x':"Total Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                ),
                                dcc.Graph(id='ss_vuln_names',
                                        figure= px.pie(ss_vuln_name_count, 
                                                        names='Total Vulnerabilities Names',
                                                        values ='Count Each Vulnerabilities',
                                                        #text_auto='.2s',
                                                        color_discrete_sequence=px.colors.sequential.haline,
                                                        title='Top 15 Vulnerabilities in SS',
                                                        labels={'x':"Total Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                ),



                        ]
        return tool_master_data
    elif pathname == "/badnitdata":
        bandit_no_of_scan = df_bandit.scan_token.count()

        #  Vuln Confidence Count
        high_count = df_bandit.vuln_confidence.str.lower().value_counts()
        bandit_vuln_names = df_bandit.vuln_name.value_counts()
        bandit_vuln_name_count = {'Vulnerabilities Name':bandit_vuln_names.keys(),
                                'Tool Count':bandit_vuln_names.values}

        # Vulnerabilities Severity_count
        vuln_severity = df_bandit.vuln_severity.value_counts()
        vuln_severity_count = {'Vulnerabilities Severity':vuln_severity.keys(),
                                'Vulnerabilities Severity Count': vuln_severity.values
                                }
        bandit_created_date ={'Vulnerabilities Created':df_bandit.created_at,
                              'Vulnerabilities ID':df_bandit.vuln_id
                                }

        bandit = [html.H1("Bandit live data visualizationsis"),
                html.Li("Total No of Scan Done So far: {}".format(bandit_no_of_scan)),
                html.Li("Total {} Vulnerabilities Severity Count:- {}".format(bandit_vuln_name_count['Vulnerabilities Name'][0],bandit_vuln_name_count['Tool Count'][0])),
                html.Li("Total {} Vulnerabilities Severity Count:- {}".format(bandit_vuln_name_count['Vulnerabilities Name'][1],bandit_vuln_name_count['Tool Count'][1])),
                html.Li("Total {} Vulnerabilities Severity Count:- {}".format(bandit_vuln_name_count['Vulnerabilities Name'][2],bandit_vuln_name_count['Tool Count'][2])),
                html.Li("Total {} Vulnerabilities Severity Count:- {}".format(vuln_severity_count['Vulnerabilities Severity'][0],vuln_severity_count['Vulnerabilities Severity Count'][0])),
                html.Li("Total {} Vulnerabilities Severity Count:- {}".format(vuln_severity_count['Vulnerabilities Severity'][1],vuln_severity_count['Vulnerabilities Severity Count'][1])),
                html.Li("Total {} Vulnerabilities Severity Count:- {}".format(vuln_severity_count['Vulnerabilities Severity'][2],vuln_severity_count['Vulnerabilities Severity Count'][2])),
                
                # Vulnerabilities Names and it Count
                dcc.Graph(id='vuln_name_bar',
                        figure= px.pie(bandit_vuln_name_count,
                                        names = 'Vulnerabilities Name',
                                        values = 'Tool Count',
                                        title='Top Vulnerabilities Name in Bandit Tool',
                                        color_discrete_sequence= px.colors.sequential.Plasma,
                                        labels={'x':"Vulnerabilities Name",'y':'Bandit Vulnerabilities Count'}),
                        config= {'displaylogo': False}
                        ),
                # Unique Vulnerabilities Creared Over Time
                dcc.Graph(id = "created_date_barchart",
                        figure= px.line(bandit_created_date , 
                                x='Vulnerabilities Created', 
                                y='Vulnerabilities ID',
                                title="Unique bandit Vulnerabilities ID's",
                                labels={'x':"Vulnerabilities Created",'y':'Vulnerabilities ID'}),
                                config= {'displaylogo': False
                        }),
                dcc.Graph(id='vuln_confidence_graph',
                         figure=px.bar(df_bandit, x='vuln_confidence',title='Vulnerabilities In Bandit Confidence'),config= {'displaylogo': False}
                         ),
                dcc.Graph(id = "vuln_severity_barchart",
                         figure=px.bar(df_bandit, x='vuln_severity',title='Vulnerabilities Severity In Bandit'),config= {'displaylogo': False}
                        ),
                dcc.Graph(id = "false_positive_barchart",
                         figure=px.pie(df_bandit, 
                                names='false_positive',
                                hole=.5,
                                color_discrete_sequence = px.colors.sequential.Darkmint,
                                values='vuln_id', title='False Positive'),config= {'displaylogo': False}
                        ),
                ]
        return bandit  
    elif pathname == "/brakemandata":
        vuln_name_count = df_brakeman.vuln_name.value_counts()
        vuln_names = df_brakeman.vuln_name.unique()
        no_of_scan = df_brakeman.scan_token.count()
        high_count = df_brakeman.vuln_confidence.str.lower().value_counts()
        brakeman = [
                    html.H1("Brakeman live data visualizationsis"),
                    html.Li("Total No of Scan Done So far: {}".format(no_of_scan)),
                    html.Li("Total No High Vulnerabilities Confidence are:- {}".format(high_count[0])),  
                    html.Li("Total No Medium Vulnerabilities Confidence are:- {}".format(high_count[1])),
                    dcc.Graph(id='vuln_name_bar',
                        figure= px.pie(df_brakeman,names=vuln_names,values=vuln_name_count ,title='Top Vulnerabilities Name in Brakeman Tool'),config= {'displaylogo': False}
                        ),
                    dcc.Graph(id = "created_date_barchart",
                        figure= px.line(df_brakeman , x='created_at', y='vuln_id',title="Unique Vulnerabilities ID's"),config= {'displaylogo': False
                        }),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_brakeman, x='tool_name',title='Tools Name'),config= {'displaylogo': False}
                            ),
                    dcc.Graph(id='bargraph',
                            figure=px.bar(df_brakeman, x='vuln_confidence',title= 'Total Vulnerabilities Confidence'),config= {'displaylogo': False}
                            ),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_brakeman, x='vuln_severity',title= 'Total Vulnerabilities Severity'),config= {'displaylogo': False}
                            ),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_brakeman, x='vuln_id',title='Vulnerabilities ID'),config= {'displaylogo': False}
                            ),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_brakeman, x='false_positive',title='False Positive'),config= {'displaylogo': False}
                            ),
            ]
        return brakeman                 
    elif pathname == "/zapdata":
        zap = [
                    html.H1("Zap live data visualizationsis"),
                    html.H4('Tools Name',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_zap, x='tool_name'),config= {'displaylogo': False}
                            ),
                    html.H4('Risk',
                        style={'textAlign':'center'}),
                    dcc.Graph(id='bargraph',
                            figure=px.bar(df_zap, x='risk_desc'),config= {'displaylogo': False}
                            ),
                    html.H4('CWE',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_zap, x='cwe'),config= {'displaylogo': False}
                            ),
                    html.H4('Vulnerabilities ID',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_zap, x='vuln_id'),config= {'displaylogo': False}
                            ),
                    html.H4('False Positive',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            #figure=px.bar(df_zap, x='false_positive'),
                            figure = px.pie(df_zap, values='false_positive',names='false_positive'),
                            #figure.show(),
                            config= {'displaylogo': False}
                            ),
            ],
        
        return zap
    elif pathname == "/phpdata":
        vuln_name_count = df_zap.vuln_name.value_counts()
        vuln_names = df_zap.vuln_name.unique()
        no_of_scan = df_zap.scan_token.count()
        high_count = df_zap.vuln_confidence.str.lower().value_counts()
        php = [        
                    html.H1("PHP live data visualizationsis"),
                    html.H1("Brakeman live data visualizationsis"),
                    html.Li("Total No of Scan Done So far: {}".format(no_of_scan)),
                    html.Li("Total No High Vulnerabilities Confidence are:- {}".format(high_count[0])),  
                    html.Li("Total No Medium Vulnerabilities Confidence are:- {}".format(high_count[1])),
                    html.H4('Tools Name',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_php, x='tool_name'),config= {'displaylogo': False}
                            ),
                    html.H4('Vulnerabilities Confidence',
                        style={'textAlign':'center'}),
                    dcc.Graph(id='bargraph',
                            figure=px.bar(df_php, x='vuln_confidence'),config= {'displaylogo': False}
                            ),
                    html.H4('Vulnerabilities Severity',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_php, x='vuln_severity'),config= {'displaylogo': False}
                            ),
                    html.H4('Vulnerabilities ID',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_php, x='vuln_id'),config= {'displaylogo': False}
                            ),
                    html.H4('False Positive',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_php, x='false_positive'),config= {'displaylogo': False}
                            ),
            ]
        return php
    elif pathname == "/nodejs":
        nodejs = zap = [
                    html.H1("Zap live data visualizationsis"),
                    html.H4('Tools Name',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_zap, x='tool_name'),config= {'displaylogo': False}
                            ),
                    html.H4('Risk',
                        style={'textAlign':'center'}),
                    dcc.Graph(id='bargraph',
                            figure=px.bar(df_zap, x='risk_desc'),config= {'displaylogo': False}
                            ),
                    html.H4('CWE',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_zap, x='cwe'),config= {'displaylogo': False}
                            ),
                    html.H4('Vulnerabilities ID',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            figure=px.bar(df_zap, x='vuln_id'),config= {'displaylogo': False}
                            ),
                    html.H4('False Positive',
                            style={'textAlign':'center'}),
                    dcc.Graph(id = "barchart",
                            #figure=px.bar(df_zap, x='false_positive'),
                            figure = px.pie(df_zap, values='false_positive',names='false_positive'),
                            #figure.show(),
                            config= {'displaylogo': False}
                            ),
            ],
        
        return zap
        return 
    elif pathname == "/semgrep":
        return [ ]
    elif pathname == "/model":
        return [ ]
    elif pathname == "/time":
        df = df_bandit.copy()
        df['Year'] = df.created_at.dt.year
        test_id_codes = []
        for i in df.test_id:
            test_id_code = int(i[1:])
            d = test_id_codes.append(test_id_code)
        df['test_id_encode'] = test_id_codes
        
        #df.vuln_id.plot(figsize=(30,15))
        #plt.ylabel("Hourly Data Created Count")

        return [html.H4('Live Hourly Vulnerabilities ID Data',
                            style={'textAlign':'center'}),
                dcc.Graph(id = "barchart", figure=px.line(df.vuln_id, x='vuln_id',title='Live Vulnerabilities ID Generated'),config= {'displaylogo': False}),
                
                html.H4("Live Weakly Vulnerabilities ID"),
                #dcc.Graph(id='weaklyVulnerabilities',figure=px.bar()),
                
                html.H4('Daily Secret Scan Tools data creation', style={'textAlign':'center'}),
                dcc.Graph(id = "Dailysecret", figure=px.line(sca_tn, x='created_at'),config= {'displaylogo': False}),
                

                    ]

    # If the user tries to reach a different page, return a 404 message
    return dbc.Container(
        [
            html.H1("404: Not found", className="text-danger"),
            html.Hr(),
            html.P(f"The pathname {pathname} was not recognised..."),
        ]
    )

if __name__=='__main__':
    app.run_server(debug=True, port=3000)

    