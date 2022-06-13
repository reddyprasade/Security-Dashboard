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

from sqlalchemy import false
warnings.filterwarnings("ignore")


def etl(table_name):
   """
       Boman.AI Database Connection from Azure Data base with configuration of user name and password and database name
       Parameters:
           table_name: We have to Pass the Table Name to fetech from DB
   """
   try:
       bomandb = mysql.connector.connect(host='host_name',
                                database='boman_dev',
                                user='bomanadmin',
                                password='password')
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
       bomandb = mysql.connector.connect(host='hostname',
                                database='boman_dev',
                                user='bomanadmin',
                                password='password')
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


vuln_name_count = sast_tn.vuln_name.value_counts()
# Vulnerabilities Severity
vuln_severity_count = sast_tn.vuln_severity.value_counts()
vuln_created_date = sast_tn.created_at.value_counts()

# SAST TOOLS
print('*'*30,'SAST TOOLS','*'*30)

# Bandit tool
print('*'*30,'SAST BANDIT(PYTHON) TOOLS','*'*30)
df_bandit = data_featching_from_db('sast_results','Bandit')

# Brakeman
print('*'*30,'SAST Brakeman TOOLS','*'*30)
df_brakeman= data_featching_from_db('sast_results','Brakeman')

# PHP
print('*'*30,'SAST PHP Code Sniffer TOOLS','*'*30)
df_php  =data_featching_from_db('sast_results','PHP Code Sniffer')

# Njsscan
print('*'*30,'SAST Njsscan TOOLS','*'*30)
df_njsscan  =data_featching_from_db('sast_results','Njsscan')
print('*'*50,'ALL SAST TOOLS ARE COMPLITED','*'*50)

# DAST TOOlS
print('*'*30,'DAST TOOLS','*'*30)
#df_zap = data_featching_from_db('dast_results','OWASP Zap')
df_zap = etl('dast_results')

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
                                dbc.DropdownMenuItem('PHP', href="/phpdata", active="exact"),
                                dbc.DropdownMenuItem('NodeJs', href="/nodejs",active='exact'),
                                dbc.DropdownMenuItem('Semgrep', href="/semgrep",active='exact'),
                                dbc.DropdownMenuItem("Zap Data", href="/zapdata", active="exact"),
                        ]),
                #dbc.NavItem(dbc.NavLink("Model", href="/model", active="exact")),
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
        # ToKen Count
        # select count(1) from boman_dev.sast_results;(SQL)
        sast_count = sast_tn.scan_token.count()   
        dast_count = dast_tn.scan_token.count()
        sc_count = sc_tn.scan_token.count()
        sca_count = sca_tn.scan_token.count()

        # Overall Scan Tools
        total_scan = {'Security Scanning Tools Names':['SAST','DAST','Secret Scan','SCA'],
                'Count of Each Scan':[sast_count,dast_count,sc_count,sca_count]}
        total_scan_count = sum(total_scan['Count of Each Scan'])

        # SAST tools Count
        sast_di = sast_tn.tool_name.value_counts()
        sast_tool_name_count = {'Tool Name':sast_di.keys(),
                                'Tool Count':sast_di.values}

        # DAST tools Count
        dast_tools_names = dast_tn.tool_name.value_counts()
        dast_tool_name_count = {'Tool Name':dast_tools_names.keys(),
                                'Tool Count':dast_tools_names.values}

        # SCA tools 
        sca_tools_names = sca_tn.tool_name.value_counts()
        sca_tool_name_count = {'Tool Name':sca_tools_names.keys(),
                                'Tool Count':sca_tools_names.values}

        # SC Tools
        sc_tool_names = sc_tn.tool_name.value_counts()
        sc_tool_names_count = {'Tool Name':sc_tool_names.keys(),
                                'Tool Count':sc_tool_names.values}

        # Total Sast Vulnerabilities Names
        sast_vuln_name = sast_tn.vuln_name.value_counts()
        sast_vuln_name_count ={'Vulnerabilities Names':sast_vuln_name.keys()[0:15],
                        "Count Each Vulnerabilities":sast_vuln_name.values[0:15]
                        }
        # Total dast Vulnerabilities Names
        dast_vuln_name = dast_tn.vuln_name.value_counts()
        dast_vuln_name_count ={'Vulnerabilities Names':dast_vuln_name.keys()[0:15],
                        "Count Each Vulnerabilities":dast_vuln_name.values[0:15]
                        }
        # Total SCA Vulnerabilities Names
        sca_vuln_name = sca_tn.vuln_name.value_counts()
        sca_vuln_name_count ={'Vulnerabilities Names':sca_vuln_name.keys()[0:15],
                        "Count Each Vulnerabilities":sca_vuln_name.values[0:15]
                        }
        # Total SS Vulnerabilities Names
        ss_vuln_name = sc_tn.vuln_name.value_counts()
        ss_vuln_name_count ={'Vulnerabilities Names':ss_vuln_name.keys()[0:15],
                        "Count Each Vulnerabilities":ss_vuln_name.values[0:15]
                        }

        # Machine Learning Model Preicated False Positive
        sast_tool_fp = sast_tn.false_positive.value_counts()
        dast_tool_fp = dast_tn.false_positive.value_counts()
        sast_fp_0=sast_tool_fp[0.0]
        dast_fp_0 = dast_tool_fp[0.0]
        total_false_postive = {'Total No of False Postive deteted by AI/ML':["False Postive",'True Postive'],
                "Count False Postive":[sast_tool_fp[1.0], dast_fp_0+sast_fp_0]
                }

        tool_master_data=[      html.H1('Boman.ai Analysis Dashboard',style={'textAlign':'center'}),
                                # Over all Scan Tools
                                
                                html.P("Overall Different Application Security Testing  Tools Which we are Listed in Below: "),
                                html.Li("This are the Top Used Security Scaners by the Customers"),
                                html.Li('Total Number of Scan Done across all the Security Scanning Tools: {}'.format(total_scan_count)),
                                #html.Hr,html.Br,
                                html.Li("Total Scan done in SAST is :...............  {}".format(sast_count)),
                                html.Li("Total Scan done in DAST is :...............  {}".format(dast_count)),
                                html.Li("Total Scan done in SCA is :................  {}".format(sca_count)),
                                html.Li("Total Scan Done in Secret Scan is :......  {}".format(sc_count)),

                                # Total Overall Security Scan Count 
                                dcc.Graph(id='Security_Scanning_Tools_bar',
                                        # Total Number of Scan Done In Overall From (SAST, DAST, SC, SCA) - Code Review tools.(X – Tool  Name and Y – No Count) 
                                        figure = px.bar(total_scan,
                                                x='Security Scanning Tools Names',
                                                y='Count of Each Scan', 
                                                text_auto='.2s',
                                                title='Total Number of Scan Done From (SAST, DAST, SC, SCA)',
                                                labels={'x':"Security Scanning Tools Names",'y':'Count of Each Scan'}),
                                        config= {'displaylogo': False}
                                ),
                                # SAST Scan Tools
                                html.Li("Scan Tools Name is  :- {}:- Count:- {}".format(sast_tool_name_count['Tool Name'][0],sast_tool_name_count['Tool Count'][0])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(sast_tool_name_count['Tool Name'][1],sast_tool_name_count['Tool Count'][1])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(sast_tool_name_count['Tool Name'][2],sast_tool_name_count['Tool Count'][2])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(sast_tool_name_count['Tool Name'][3],sast_tool_name_count['Tool Count'][3])),

                                dcc.Graph(id ='Tool_name_barchart',
                                        figure= px.bar(sast_tool_name_count, x='Tool Name',y='Tool Count',
                                                text_auto='.2s',title='All SAST Scan Tool',labels={'x':"Tools Names ",'y':'Count of Each Scan Tools'}),
                                        config= {'displaylogo': False}
                                ),
                                # DAST Scan Tools
                                html.Li("Scan Tools Name is  :- {}:- Count:- {}".format(dast_tool_name_count['Tool Name'][0],dast_tool_name_count['Tool Count'][0])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][1],dast_tool_name_count['Tool Count'][1])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][2],dast_tool_name_count['Tool Count'][2])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][3],dast_tool_name_count['Tool Count'][3])),
                                dcc.Graph(id ='Tool_name_barchart',
                                        figure= px.bar(dast_tool_name_count, x='Tool Name',y='Tool Count',
                                                text_auto='.2s',title='All DAST Scan Type',
                                                color_discrete_sequence = px.colors.sequential.Plasma,
                                                labels={'x':"Tools Names Type ",'y':'Count of Each Scan Tools'}
                                                ),
                                        config= {'displaylogo': False}
                                ),
                                # SCA Scan Tools 
                                html.Li("Scan Tools Name is  :- {}:- Count:- {}".format(sca_tool_name_count['Tool Name'][0],sca_tool_name_count['Tool Count'][0])),
                                #html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][1],dast_tool_name_count['Tool Count'][1])),
                                #html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][2],dast_tool_name_count['Tool Count'][2])),
                                #html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][3],dast_tool_name_count['Tool Count'][3])),

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
                                html.Li("Scan Tools Name is  :- {}:- Count:- {}".format(sc_tool_names_count['Tool Name'][0],sc_tool_names_count['Tool Count'][0])),
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
                                html.H4('Total Vulnerabilities from both SAST & DAST Predicate by Machine Learning Model'),
                                html.Li('Total No Of Results Processed by AI/ML API is:- {}'.format(sum(total_false_postive['Count False Postive']))),
                                html.Li("Total No of False Postive Deteeced by AI/ML API:- {}".format(total_false_postive['Count False Postive'][0])),
                                html.Li("Total No of True Postive Deteeced by AI/ML API:- {}".format(total_false_postive['Count False Postive'][1])),
                                dcc.Graph(id='false_postive_bar',
                                        # false positive vulnerability in  application (1)      
                                        # false nagative no vulnerability in application (0)
                                        #figure = px.bar(total_false_postive, x='False Postive and Negative Found',y = 'Count False Postive and Negative',text_auto='.2s',title='Total Vulnerabilities in SAST & DAST Predicate by Machine Learning Model'),
                                        config= {'displaylogo': False},
                                        figure = px.pie(total_false_postive, 
                                                names='Total No of False Postive deteted by AI/ML',
                                                hole=.7,
                                                color_discrete_sequence=px.colors.sequential.Sunsetdark,
                                                values = 'Count False Postive', 
                                                title='Total Vulnerabilities in SAST DAST Predicate by Machine Learning Model')
                                ),
                                dcc.Graph(id='Sast_vuln_names',
                                        figure= px.pie(sast_vuln_name_count, names='Vulnerabilities Names',values='Count Each Vulnerabilities',
                                                        #text_auto='.2s',
                                                        hole=.1,
                                                        color_discrete_sequence=px.colors.sequential.Plasma,
                                                        title='Top 15 Vulnerabilities in SAST',
                                                        labels={'x':"Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                  ),
                                dcc.Graph(id='dast_vuln_names',
                                        figure= px.bar(dast_vuln_name_count, x='Vulnerabilities Names',y='Count Each Vulnerabilities',
                                                        text_auto='.2s', 
                                                        color_discrete_sequence=px.colors.sequential.RdBu,
                                                        title='Top 15 Vulnerabilities in DAST'),
                                                        #labels={'x':"Total Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                ),
                                dcc.Graph(id='sca_vuln_names',
                                        figure= px.pie(sca_vuln_name_count, names='Vulnerabilities Names',values='Count Each Vulnerabilities',
                                                        #text_auto='.2s',
                                                        hole=.3,
                                                        color_discrete_sequence=px.colors.sequential.Rainbow,
                                                        title='Top 15 Vulnerabilities in SCA',
                                                        labels={'x':"Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                ),
                                #dcc.Graph(id='ss_vuln_names',
                                #        figure= px.pie(ss_vuln_name_count, 
                                #                        names='Total Vulnerabilities Names',
                                #                       #text_auto='.2s',
                                #                        color_discrete_sequence=px.colors.sequential.haline,
                                #                        title='Top 15 Vulnerabilities in SS',
                                #                        labels={'x':"Total Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                #        config= {'displaylogo': False},
                                #),

                        ]
        return tool_master_data
    elif pathname == "/badnitdata":
        bandit_no_of_scan = df_bandit.scan_token.count()

        #  Vulnerabilities Names Count
        bandit_vuln_names = df_bandit.vuln_name.value_counts()
        bandit_vuln_name_count = {'Vulnerabilities Name':bandit_vuln_names.keys(),
                                'Tool Count':bandit_vuln_names.values}
        # Vulnerabilities Severity_count
        bandit_vuln_severity = df_bandit.vuln_severity.value_counts()
        bandit_vuln_severity_count = {'Vulnerabilities Severity':bandit_vuln_severity.keys(),
                                'Vulnerabilities Count': bandit_vuln_severity.values
                                }
        # Vulnerabilities Confidence Count
        bandit_vuln_confidence = df_bandit.vuln_confidence.value_counts()
        bandit_vuln_confidence_count = {'Vulnerabilities Confidence':bandit_vuln_confidence.keys(),
                        'Vulnerabilities Count': bandit_vuln_confidence.values
                        }
        # False Postive Data 
        bandit_false_postive = df_bandit['false_positive'].value_counts()
        bandit_false_postive_count = {'False Positive':bandit_false_postive.keys(),
                        'False Positive Count': bandit_false_postive.values
                        }

        bandit = [html.H1("Bandit live data visualizationsis"),
                html.Li("Total No of Scan Done So far: {}".format(bandit_no_of_scan)),
                html.Li("Vulnerabilities Name:- {}  Vulnerabilities Count:- {}".format(bandit_vuln_name_count['Vulnerabilities Name'][0],bandit_vuln_name_count['Tool Count'][0])),
                html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(bandit_vuln_name_count['Vulnerabilities Name'][1],bandit_vuln_name_count['Tool Count'][1])),
                html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(bandit_vuln_name_count['Vulnerabilities Name'][2],bandit_vuln_name_count['Tool Count'][2])),
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
                #dcc.Graph(id = "created_date_barchart",
                #        figure= px.line(bandit_created_date , 
                #                x='Vulnerabilities Created', 
                #                y='Vulnerabilities Count',
                #                title="Unique bandit Vulnerabilities",
                #                labels={'x':"Vulnerabilities Created",'y':'Vulnerabilities Count'}),
                #                config= {'displaylogo': False
                #        }),

                # Bandit Vulnerabilities Severity
                html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(bandit_vuln_severity_count['Vulnerabilities Severity'][0],bandit_vuln_severity_count['Vulnerabilities Count'][0])),
                html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(bandit_vuln_severity_count['Vulnerabilities Severity'][1],bandit_vuln_severity_count['Vulnerabilities Count'][1])),
                html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(bandit_vuln_severity_count['Vulnerabilities Severity'][2],bandit_vuln_severity_count['Vulnerabilities Count'][2])),
                
                dcc.Graph(id='vuln_severity_graph',
                         figure=px.bar(bandit_vuln_severity_count, 
                                        x='Vulnerabilities Severity',
                                        y = 'Vulnerabilities Count',
                                        title='Vulnerabilities Severity In Bandit Scan Tool'),config= {'displaylogo': False}
                         ),

                # Bandit Vulnerabilities Confidence
                html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(bandit_vuln_confidence_count['Vulnerabilities Confidence'][0],bandit_vuln_confidence_count['Vulnerabilities Count'][0])),
                html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(bandit_vuln_confidence_count['Vulnerabilities Confidence'][1],bandit_vuln_confidence_count['Vulnerabilities Count'][1])),
                html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(bandit_vuln_confidence_count['Vulnerabilities Confidence'][2],bandit_vuln_confidence_count['Vulnerabilities Count'][2])),
                dcc.Graph(id = "vuln_severity_barchart",
                         figure=px.bar(bandit_vuln_confidence_count, 
                                        x='Vulnerabilities Confidence',
                                        y = 'Vulnerabilities Count',
                                        color_discrete_sequence= px.colors.sequential.OrRd,
                                        title='Vulnerabilities Severity In Bandit'),config= {'displaylogo': False}
                        ),
                # Total No False Positive and Nagative
                html.H4("Total No Result Processed by Bandit Machine Learning Model API is:- {}".format(sum(bandit_false_postive_count['False Positive Count']))),
                html.Li("True Positive is : {} :-  Count:- {}".format(bandit_false_postive_count['False Positive'][0],bandit_false_postive_count['False Positive Count'][0])),
                html.Li("False Postive is : {} :-   Count:- {}".format(bandit_false_postive_count['False Positive'][1],bandit_false_postive_count['False Positive Count'][1])),
                dcc.Graph(id = "false_positive_barchart",
                         figure=px.pie(bandit_false_postive_count, 
                                names = 'False Positive',
                                 hole = .5,
                                color_discrete_sequence = px.colors.sequential.Darkmint,
                                values = 'False Positive Count', 
                                title='False Positive'),config= {'displaylogo': False}
                        ),
                ]
        return bandit
    elif pathname == "/brakemandata":
        brakeman_no_of_scan = df_brakeman.scan_token.count()

        #  Vulnerabilities Names Count
        brakeman_high_count = df_brakeman.vuln_confidence.str.lower().value_counts()
        brakeman_vuln_names = df_brakeman.vuln_name.value_counts()
        brakeman_vuln_name_count = {'Vulnerabilities Name':brakeman_vuln_names.keys(),
                                'Tool Count':brakeman_vuln_names.values}

        # Vulnerabilities Severity_count
        brakeman_vuln_severity = df_brakeman.vuln_severity.value_counts()
        brakeman_vuln_severity_count = {'Vulnerabilities Severity':brakeman_vuln_severity.keys(),
                                'Vulnerabilities Count': brakeman_vuln_severity.values
                                }
        # Created Date
        brakeman_created_date ={'Vulnerabilities Created':df_brakeman.created_at,
                              'Vulnerabilities Count':df_brakeman.vuln_id
                                }

        # Vulnerabilities Confidence Count
        brakeman_vuln_confidence = df_brakeman.vuln_confidence.value_counts()
        brakeman_vuln_confidence_count = {'Vulnerabilities Confidence':brakeman_vuln_confidence.keys(),
                        'Vulnerabilities Count': brakeman_vuln_confidence.values
                        }
        # False Postive Data 
        brakeman_false_postive = df_brakeman['false_positive'].value_counts()
        brakeman_false_postive_count = {'False Positive':brakeman_false_postive.keys(),
                        'False Positive Count': brakeman_false_postive.values
                        }

        #brakeman_vuln_name_count = df_brakeman.vuln_name.value_counts()
        #brakeman_vuln_names = df_brakeman.vuln_name.unique()
        #brakeman_no_of_scan = df_brakeman.scan_token.count()
        brakeman_high_count = df_brakeman.vuln_confidence.str.lower().value_counts()
        
        brakeman = [
                html.H1("Brakeman live data visualizationsis"),
                html.Li("Total No of Scan Done So far: {}".format(brakeman_no_of_scan)),
                html.Li("Vulnerabilities Name:- {}  Vulnerabilities Count:- {}".format(brakeman_vuln_name_count['Vulnerabilities Name'][0],brakeman_vuln_name_count['Tool Count'][0])),
                html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(brakeman_vuln_name_count['Vulnerabilities Name'][1],brakeman_vuln_name_count['Tool Count'][1])),
                html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(brakeman_vuln_name_count['Vulnerabilities Name'][2],brakeman_vuln_name_count['Tool Count'][2])),
                # Vulnerabilities Names and it Count
                dcc.Graph(id='vuln_name_bar',
                        figure= px.pie(brakeman_vuln_name_count,
                                        names = 'Vulnerabilities Name',
                                        values = 'Tool Count',
                                        title='Top Vulnerabilities Name in Brakeman Tool',
                                        color_discrete_sequence= px.colors.sequential.Plasma,
                                        labels={'x':"Vulnerabilities Name",'y':'Brakeman Vulnerabilities Count'}),
                        config= {'displaylogo': False}
                        ),
                
                # Brakeman Vulnerabilities Severity
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(brakeman_vuln_severity_count['Vulnerabilities Severity'][0],brakeman_vuln_severity_count['Vulnerabilities Count'][0])),
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(brakeman_vuln_severity_count['Vulnerabilities Severity'][1],brakeman_vuln_severity_count['Vulnerabilities Count'][1])),
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(brakeman_vuln_severity_count['Vulnerabilities Severity'][2],brakeman_vuln_severity_count['Vulnerabilities Count'][2])),
                
                #dcc.Graph(id='vuln_severity_graph',
                #         figure=px.bar(brakeman_vuln_severity_count, 
                #                        x='Vulnerabilities Severity',
                #                        y = 'Vulnerabilities Count',
                #                        title='Vulnerabilities Severity In Brakeman Scan Tool'),config= {'displaylogo': False}
                #         ),

                # Brakeman Vulnerabilities Confidence
                html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(brakeman_vuln_confidence_count['Vulnerabilities Confidence'][0],brakeman_vuln_confidence_count['Vulnerabilities Count'][0])),
                html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(brakeman_vuln_confidence_count['Vulnerabilities Confidence'][1],brakeman_vuln_confidence_count['Vulnerabilities Count'][1])),
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(brakeman_vuln_confidence_count['Vulnerabilities Confidence'][2],brakeman_vuln_confidence_count['Vulnerabilities Count'][2])),
                dcc.Graph(id = "vuln_severity_barchart",
                         figure=px.bar(brakeman_vuln_confidence_count, 
                                        x='Vulnerabilities Confidence',
                                        y = 'Vulnerabilities Count',
                                        color_discrete_sequence= px.colors.sequential.OrRd,
                                        title='Vulnerabilities Severity In Brakeman'),config= {'displaylogo': False}
                        ),
                # Total No False Positive and Nagative
                html.H4("Total No Result Processed by Brakeman Machine Learning Model API is:- {}".format(sum(brakeman_false_postive_count['False Positive Count']))),
                html.Li("True Positive is : {} :-  Count:- {}".format(brakeman_false_postive_count['False Positive'][0],brakeman_false_postive_count['False Positive Count'][0])),
                html.Li("False Postive is : {} :-   Count:- {}".format(brakeman_false_postive_count['False Positive'][1],brakeman_false_postive_count['False Positive Count'][1])),
                dcc.Graph(id = "false_positive_barchart",
                         figure=px.pie(brakeman_false_postive_count, 
                                names = 'False Positive',
                                hole = .5,
                                color_discrete_sequence = px.colors.sequential.Darkmint,
                                values = 'False Positive Count', 
                                title='False Positive'),config= {'displaylogo': False}
                        ),
                ]
        return brakeman                 
    elif pathname == "/phpdata":
        php_no_of_scan = df_php.scan_token.count()

        #  Vulnerabilities Names Count
        brakeman_high_count = df_php.vuln_confidence.str.lower().value_counts()
        php_vuln_names = df_php.vuln_name.value_counts()
        php_vuln_name_count = {'Vulnerabilities Name':php_vuln_names.keys(),
                                'Tool Count':php_vuln_names.values}

        # Vulnerabilities Severity_count
        php_vuln_severity = df_php.vuln_severity.value_counts()
        php_vuln_severity_count = {'Vulnerabilities Severity': php_vuln_severity.keys(),
                                'Vulnerabilities Count': php_vuln_severity.values
                                }
        # Created Date
        php_created_date ={'Vulnerabilities Created':df_php.created_at,
                              'Vulnerabilities Count':df_php.vuln_id
                                }

        # Vulnerabilities Confidence Count
        php_vuln_confidence = df_php.vuln_confidence.value_counts()
        php_vuln_confidence_count = {'Vulnerabilities Confidence':php_vuln_confidence.keys(),
                        'Vulnerabilities Count': php_vuln_confidence.values
                        }
        # False Postive Data 
        php_false_postive = df_php['false_positive'].value_counts()
        php_false_postive_count = {'False Positive':php_false_postive.keys(),
                        'False Positive Count': php_false_postive.values
                        }
        # Unique Scan Details
        scan_details_id = df_php.scan_details_id.value_counts()
        scan_details_id_count = {'Unique Scan Id':scan_details_id.keys(),
                                'Count of Scan':scan_details_id.values
                                }
        
        php = [
                html.H1("PHP live data visualizationsis"),
                html.Li("Total No of Scan Done So far: {}".format(php_no_of_scan)),
                html.Li("Vulnerabilities Name:- {}  Vulnerabilities Count:- {}".format(php_vuln_name_count['Vulnerabilities Name'][0],php_vuln_name_count['Tool Count'][0])),
                html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(php_vuln_name_count['Vulnerabilities Name'][1],php_vuln_name_count['Tool Count'][1])),
                html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(php_vuln_name_count['Vulnerabilities Name'][2],php_vuln_name_count['Tool Count'][2])),
                html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(php_vuln_name_count['Vulnerabilities Name'][3],php_vuln_name_count['Tool Count'][3])),
                html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(php_vuln_name_count['Vulnerabilities Name'][4],php_vuln_name_count['Tool Count'][4])),
                # Vulnerabilities Names and it Count
                dcc.Graph(id='vuln_name_bar',
                        figure= px.pie(php_vuln_name_count,
                                        names = 'Vulnerabilities Name',
                                        values = 'Tool Count',
                                        hole=.2,
                                        title='Top Vulnerabilities Name in PHP Tool',
                                        color_discrete_sequence= px.colors.sequential.Plasma,
                                        labels={'x':"Vulnerabilities Name",'y':'PHP Vulnerabilities Count'}),
                        config= {'displaylogo': False}
                        ),
                
                # PHP Vulnerabilities Severity
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(php_vuln_severity_count['Vulnerabilities Severity'][0],php_vuln_severity_count['Vulnerabilities Count'][0])),
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(php_vuln_severity_count['Vulnerabilities Severity'][1],php_vuln_severity_count['Vulnerabilities Count'][1])),
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(php_vuln_severity_count['Vulnerabilities Severity'][2],php_vuln_severity_count['Vulnerabilities Count'][2])),
                
                #dcc.Graph(id='vuln_severity_graph',
                #         figure=px.pie(php_vuln_severity_count, 
                #                        names='Vulnerabilities Severity',
                #                        values= 'Vulnerabilities Count',
                #                        hole=.3,
                #                        opacity = .3,
                #                        #hover_data="label+percent+name",
                #                        title='Vulnerabilities Severity In PHP Scan Tool'),config= {'displaylogo': False}
                #         ),

                # PHP Vulnerabilities Confidence
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(php_vuln_confidence_count['Vulnerabilities Confidence'][0],php_vuln_confidence_count['Vulnerabilities Count'][0])),
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(php_vuln_confidence_count['Vulnerabilities Confidence'][1],php_vuln_confidence_count['Vulnerabilities Count'][1])),
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(php_vuln_confidence_count['Vulnerabilities Confidence'][2],php_vuln_confidence_count['Vulnerabilities Count'][2])),
                #dcc.Graph(id = "vuln_severity_barchart",
                #         figure=px.bar(php_vuln_confidence_count, 
                #                        x='Vulnerabilities Confidence',
                #                        y = 'Vulnerabilities Count',
                #                        color_discrete_sequence= px.colors.sequential.OrRd,
                #                        title='Vulnerabilities Severity In PHP'),config= {'displaylogo': False}
                #        ),
                # Total No False Positive and Nagative
                #html.H4("Total No Result Processed by PHP Machine Learning Model API is:- {}".format(sum(php_false_postive_count['False Positive Count']))),
                #html.Li("True Positive is : {} :-  Count:- {}".format(php_false_postive_count['False Positive'][0],php_false_postive_count['False Positive Count'][0])),
                #html.Li("False Postive is : {} :-   Count:- {}".format(php_false_postive_count['False Positive'][1],php_false_postive_count['False Positive Count'][1])),
                #dcc.Graph(id = "false_positive_barchart",
                #         figure=px.pie(php_false_postive_count, 
                #                names = 'False Positive',
                #                hole = .5,
                #                color_discrete_sequence = px.colors.sequential.Darkmint,
                #                values = 'False Positive Count', 
                #                title='False Positive'),config= {'displaylogo': False}
                #        ),
                # Scan Detials
                dcc.Graph(id='scan-details-bar',
                        figure= px.bar(scan_details_id_count,
                                        x = 'Unique Scan Id',
                                        y = 'Count of Scan',
                                        title='Top Vulnerabilities Name in PHP Tool',
                                        color_discrete_sequence= px.colors.sequential.Plasma,
                                        ),
                        config= {'displaylogo': False}
                        ),
                ]
        return php
    elif pathname == "/nodejs":
        nodejs_no_of_scan = df_njsscan.scan_token.count()

        #  Vulnerabilities Names Count
        nodejs_high_count = df_njsscan.vuln_confidence.str.lower().value_counts()
        nodejs_vuln_names = df_njsscan.vuln_name.value_counts()
        nodejs_vuln_name_count = {'Vulnerabilities Name':nodejs_vuln_names.keys(),
                                'Tool Count':nodejs_vuln_names.values}

        # Vulnerabilities Severity_count
        nodejs_vuln_severity = df_njsscan.vuln_severity.value_counts()
        nodejs_vuln_severity_count = {'Vulnerabilities Severity':nodejs_vuln_severity.keys(),
                                'Vulnerabilities Count': nodejs_vuln_severity.values
        }

        # Vulnerabilities Confidence Count
        nodejs_vuln_confidence = df_njsscan.vuln_confidence.value_counts()
        nodejs_vuln_confidence_count = {'Vulnerabilities Confidence':nodejs_vuln_confidence.keys(),
                        'Vulnerabilities Count': nodejs_vuln_confidence.values
                        }
        # False Postive Data 
        nodejs_false_postive = df_njsscan['false_positive'].value_counts()
        nodejs_false_postive_count = {'False Positive':nodejs_false_postive.keys(),
                        'False Positive Count': nodejs_false_postive.values
                        }

        #brakeman_vuln_name_count = df_brakeman.vuln_name.value_counts()
        #brakeman_vuln_names = df_brakeman.vuln_name.unique()
        #brakeman_no_of_scan = df_brakeman.scan_token.count()
        nodejs_high_count = df_njsscan.vuln_confidence.str.lower().value_counts()
        
        nodejs = [        
                html.H1("Nodejs live data visualizationsis"),
                html.Li("Total No of Scan Done So far: {}".format(nodejs_no_of_scan)),

                # Vulnerabilities Names and it Count
                html.Li("Vulnerabilities Name:- {}  Vulnerabilities Count:- {}".format(nodejs_vuln_name_count['Vulnerabilities Name'][0],nodejs_vuln_name_count['Tool Count'][0])),
                #html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(nodejs_vuln_name_count['Vulnerabilities Name'][1],nodejs_vuln_name_count['Tool Count'][1])),
                #html.Li("Vulnerabilities Name:- {} Vulnerabilities Count:- {}".format(nodejs_vuln_name_count['Vulnerabilities Name'][2],nodejs_vuln_name_count['Tool Count'][2])),
                
                
                dcc.Graph(id='vuln_name_bar',
                        figure= px.pie(nodejs_vuln_name_count,
                                        names = 'Vulnerabilities Name',
                                        values = 'Tool Count',
                                        title='Top Vulnerabilities Name in Nodejs Tool',
                                        color_discrete_sequence= px.colors.sequential.Plasma,
                                        labels={'x':"Vulnerabilities Name",'y':'Nodejs Vulnerabilities Count'}),
                        config= {'displaylogo': False}
                        ),
                
                # NodeJs Vulnerabilities Severity
                html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(nodejs_vuln_severity_count['Vulnerabilities Severity'][0],nodejs_vuln_severity_count['Vulnerabilities Count'][0])),
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(nodejs_vuln_severity_count['Vulnerabilities Severity'][1],nodejs_vuln_severity_count['Vulnerabilities Count'][1])),
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(nodejs_vuln_severity_count['Vulnerabilities Severity'][2],nodejs_vuln_severity_count['Vulnerabilities Count'][2])),
                
                dcc.Graph(id='vuln_severity_graph',
                         figure=px.bar(nodejs_vuln_severity_count, 
                                        x='Vulnerabilities Severity',
                                        y = 'Vulnerabilities Count',
                                        title='Vulnerabilities Severity In Nodejs Scan Tool'),config= {'displaylogo': False}
                         ),

                # Nodejs Vulnerabilities Confidence
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(nodejs_vuln_confidence_count['Vulnerabilities Confidence'][0],brakeman_vuln_confidence_count['Vulnerabilities Count'][0])),
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(nodejs_vuln_confidence_count['Vulnerabilities Confidence'][1],brakeman_vuln_confidence_count['Vulnerabilities Count'][1])),
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(brakeman_vuln_confidence_count['Vulnerabilities Confidence'][2],brakeman_vuln_confidence_count['Vulnerabilities Count'][2])),
                #dcc.Graph(id = "vuln_severity_barchart",
                #         figure=px.bar(brakeman_vuln_confidence_count, 
                #                        x='Vulnerabilities Confidence',
                #                        y = 'Vulnerabilities Count',
                #                        color_discrete_sequence= px.colors.sequential.OrRd,
                #                        title='Vulnerabilities Severity In Nodejs'),config= {'displaylogo': False}
                #        ),
                # Total No False Positive and Nagative
                html.H4("Total No Result Processed by Bandit Machine Learning Model API is:- {}".format(sum(nodejs_false_postive_count['False Positive Count']))),
                html.Li("True Positive is : {} :-  Count:- {}".format(nodejs_false_postive_count['False Positive'][0],nodejs_false_postive_count['False Positive Count'][0])),
                #html.Li("False Postive is : {} :-   Count:- {}".format(brakeman_false_postive_count['False Positive'][1],brakeman_false_postive_count['False Positive Count'][1])),
                dcc.Graph(id = "false_positive_barchart",
                         figure=px.pie(nodejs_false_postive_count, 
                                names = 'False Positive',
                                hole = .5,
                                color_discrete_sequence = px.colors.sequential.Darkmint,
                                values = 'False Positive Count', 
                                title='False Positive'),config= {'displaylogo': False}
                        ),
            ]

        return nodejs
    elif pathname == "/semgrep":
        return [ ]
    elif pathname == "/zapdata":
        # Zap Scan Token count
        zap_no_of_scan = df_zap.scan_token.count()
        zap_tool_names  = df_zap.tool_name.value_counts()
        zap_tool_names_count = {'Tool Names':zap_tool_names.keys(),
                                'Count':zap_tool_names.values
                                }
        # Vulnerability Names 
        zap_vuln_name = df_zap.vuln_name.value_counts()
        zap_vuln_names_count = {'Vulnerability Name':zap_vuln_name.keys(),
                                "Vulnerability Count":zap_vuln_name.values}

        risk_code = df_zap.risk_code.value_counts()
        risk_code_count = {'Risk Code':risk_code.keys(),
                        "Risk Count":risk_code.values}
        confidence = df_zap.confidence.value_counts()
        confidence_code = {'Confidence':confidence.keys(),
                        'Count':confidence.values}
        risk_desc  = df_zap.risk_desc.value_counts()
        risk_desc_count = {'Risk desc':risk_desc.keys(),'Count':risk_desc.values}

        cwe = df_zap.cwe.value_counts()
        cwe_count = {'CWE No':cwe.keys(),"CWE Count":cwe.values}

        zap = [ html.H2('Zap Live Dashboard:'),
                html.Li("Total No of Scan Done so far: {} ".format(zap_no_of_scan)),
                html.H4('Different Scan Done With Different Tool Names'),
                html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][0],zap_tool_names_count['Count'][0])),
                html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][1],zap_tool_names_count['Count'][1])),
                html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][2],zap_tool_names_count['Count'][2])),
                html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][3],zap_tool_names_count['Count'][3])),
                html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][4],zap_tool_names_count['Count'][4])),
                dcc.Graph(id='tool_bar',
                        figure= px.bar(zap_tool_names_count,
                                        x = 'Tool Names',
                                        y = 'Count',
                                        title='Top Tool Name in ZAP Tool',
                                        color_discrete_sequence= px.colors.sequential.Plasma,
                                        text_auto='.2s',
                                        labels={'x':"Tool Name",'y':'Zap Tool Count'}),
                        config= {'displaylogo': False},
                        ),
                html.H5('Total Vulnerability Found in OWASP ZAP: {}'.format(sum(zap_vuln_names_count[ "Vulnerability Count"]))),
                dcc.Graph(id='vuln_name_bar',
                        figure= px.pie(zap_vuln_names_count,
                                        names = 'Vulnerability Name',
                                        values = 'Vulnerability Count',
                                        hole=0.5,
                                        title='Top Vulnerabilities Name in ZAP Tool',
                                        color_discrete_sequence= px.colors.sequential.Plasma,
                                        labels={'x':"Vulnerabilities Name",'y':'Zap Vulnerabilities Count'}),
                        config= {'displaylogo': False},
                        ),
                html.H5('Total Risk Code in Zap tools {}'.format(sum(risk_code.values))),
                dcc.Graph(id='risk_bar',
                        figure= px.bar(risk_code_count,
                                        x = 'Risk Code',
                                        y = 'Risk Count',
                                        title='Top Risk Count in ZAP Tool',
                                        color_discrete_sequence= px.colors.sequential.Plasma,
                                        text_auto='.2s',
                                        ),
                        config= {'displaylogo': False},
                        ),
                html.H5("Total count Common Weakness Enumeration (cwe): {}".format(sum(cwe_count['CWE Count']))),
                dcc.Graph(id='cwe_bar',
                        figure= px.pie(cwe_count,
                                names= 'CWE No',
                                values= 'CWE Count',
                                title='Risk Desc in ZAP Tool',
                                hole=.4,
                                color_discrete_sequence= px.colors.sequential.Plasma),
                        config= {'displaylogo': False}
                        ),
                html.H5('Total Confidence  in Zap tools {}'.format(sum(confidence.values))),
                dcc.Graph(id='risk_bar',
                        figure= px.bar(confidence_code,
                                        x = 'Confidence',
                                        y = 'Count',
                                        title='Top Confidence in ZAP Tool',
                                        color_discrete_sequence= px.colors.sequential.Plasma,
                                        text_auto='.2s',
                                        ),
                        config= {'displaylogo': False},
                        ),
                dcc.Graph(id='risk_desc_pie',
                        figure= px.pie(risk_desc_count,
                                names= 'Risk desc',
                                values= 'Count',
                                title='Risk Desc in ZAP Tool',
                                hole=.4,
                                color_discrete_sequence= px.colors.sequential.Plasma
                                ),
                        config= {'displaylogo': False}
                        ),
                
        ] 
        return zap
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

    
