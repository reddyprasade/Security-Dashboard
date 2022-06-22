from tkinter import CENTER
from zlib import DEF_BUF_SIZE
import dash
import dash_bootstrap_components as dbc
import dash_html_components as html
import dash_core_components as dcc
from matplotlib.pyplot import figure
import plotly.express as px
from dash.dependencies import Input, Output
import pandas as pd
import pymongo as pm

import plotly.graph_objects as go
import warnings

from sqlalchemy import false
warnings.filterwarnings("ignore")


def connect_mongo(host, port, username, password, db):
    """ A util for making a connection to mongo """
    try:
        if username and password:
            mongo_uri = 'mongodb://%s:%s@%s:%s/%s' % (username, password, host, port, db)
            conn = pm.MongoClient(mongo_uri)
        else:
            conn = pm.MongoClient(host, port)
        return conn[db]
    except Exception as e:
        print("Mongo Connection error",e)
    finally:
        print("Mongo Connection Close")

def read_mongo(db, collection, query={}, host='127.0.0.1', port=27017, username=None, password=None, no_id=True):
    """ Read from Mongo and Store into DataFrame """

    # Connect to MongoDB
    db = connect_mongo(host=host, port=port, username=username, password=password, db=db)

    # Make a query to the specific DB and Collection
    cursor = db[collection].find(query)

    # Expand the cursor and construct the DataFrame
    df =  pd.DataFrame(list(cursor))

    # Delete the _id
    if no_id:
        del df['_id']

    return df

# Tools info
print('*'*30,'ALL APPLICATION SECURITY TOOLS ','*'*30)
sast_result = read_mongo('boman_dev','Vulnerabilities',query={'tool_type': 'SAST'})
dast_result = read_mongo('boman_dev','Vulnerabilities',query={'tool_type': 'DAST'})
sca_result = read_mongo('boman_dev','Vulnerabilities',query={'tool_type': 'SCA'})
secret_scanner_results = read_mongo('boman_dev','Vulnerabilities',query={'tool_type': 'Secret Scanner'})
vuln = read_mongo('boman_dev','Vulnerabilities')

vuln_name_count = sast_result.vuln_name.value_counts()

def Repeated_Vulnerabilities_across_applications():
        di = {}
        sast_tn_vuln_name = dict(sast_result.vuln_name.value_counts())
        dast_tn_vuln_name = dict(dast_result.vuln_name.value_counts())
        sca_tn_vuln_name = dict(sca_result.vuln_name.value_counts())
        #sc_tn_vuln_name = dict(secret_scanner_results.vuln_name.value_counts())
        di.update(sast_tn_vuln_name)
        di.update(dast_tn_vuln_name)
        di.update(sca_tn_vuln_name)
        #di.update(sc_tn_vuln_name)
        data = dict({'Vulnerabilities Names':list(di.keys()),"Count":list(di.values())})
        df = pd.DataFrame(data)
        top10 = df.nlargest(n=10, columns=['Count'])
        return top10

def vulnerabilities_severity(tool_name):
        # SAST Vulnerabilities Severity
        vuln_severity = tool_name.boman_severity.value_counts()
        vuln_severity_count = {'Vulnerabilities Severity':vuln_severity.keys(),
                             'Vulnerabilities Count': vuln_severity.values
                           }
        return vuln_severity_count
# SAST TOOLS`x`
print('*'*30,'SAST TOOLS','*'*30)

# Bandit tool
print('*'*30,'SAST BANDIT TOOLS','*'*30)
df_bandit = read_mongo('boman_dev','Vulnerabilities',query={'tool_type': 'SAST','tool_name':'Bandit'})

# Brakeman
print('*'*30,'SAST Brakeman TOOLS','*'*30)
df_brakeman= read_mongo('boman_dev','Vulnerabilities',query={'tool_type': 'SAST','tool_name':'Brakeman'})


# PHP
print('*'*30,'SAST PHP Code Sniffer TOOLS','*'*30)
df_php  = read_mongo('boman_dev','Vulnerabilities',query={'tool_type': 'SAST','tool_name':'PHP Code Sniffer'})

# Njsscan
print('*'*30,'SAST Njsscan TOOLS','*'*30)
df_njsscan  = read_mongo('boman_dev','Vulnerabilities',query={'tool_type': 'SAST','tool_name':'Njsscan'})
print('*'*50,'ALL SAST TOOLS ARE COMPLITED','*'*50)

# DAST TOOlS
print('*'*30,'DAST TOOLS','*'*30)
#df_zap = data_featching_from_db('dast_results','OWASP Zap')
df_zap = read_mongo('boman_dev','Vulnerabilities',query={'tool_type': 'DAST'})

app = dash.Dash(__name__, external_stylesheets=[dbc.themes.UNITED]) #dbc.themes.UNITED
app.title = "Boman.ai Dashboard"

def top_three_peak():
        by_date = pd.Series(vuln['created_at']).value_counts().sort_index()
        by_date.index = pd.DatetimeIndex(by_date.index)
        df_date = by_date.rename_axis('Issues_created').reset_index(name='counts')
        top_dates = df_date.sort_values(by=['counts'],ascending=False).head(3)
        vals = []
        for tgl, tot in zip(top_dates["Issues_created"], top_dates["counts"]):
                tgl = tgl.strftime("%d %B")
                val = "%d (%s)"%(tot, tgl)
                vals.append(val)

        top_dates['tgl'] = vals

        fig = go.Figure(data=go.Scatter(x=df_date['Issues_created'].astype(dtype=str), 
                                y=df_date['counts'],
                                marker_color='gray', text="counts"))
        fig.update_layout({"title": 'Top three peak dates',
                   "xaxis": {"title":"Time"},
                   "yaxis": {"title":"Total Issues"},
                   "showlegend": False})
        fig.add_traces(go.Scatter(x=top_dates['Issues_created'], y=top_dates['counts'],
                          textposition='top left',
                          textfont=dict(color='#233a77'),
                          mode='markers+text',
                          marker=dict(color='red', size=3),
                          text = top_dates["tgl"]))
        return fig
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
                #dbc.NavLink("Home", href="www.boman.ai", active="exact"),
                dbc.NavLink("Home", href="/dashboard", active="exact"),
                dbc.DropdownMenu(
                        label="Tools Dashboard",
                        nav=True,
                        children=[
                                dbc.DropdownMenuItem("Bandit Data", href="/badnitdata", active="exact"),
                                dbc.DropdownMenuItem("Brakeman Data", href="/brakemandata", active="exact"),
                                dbc.DropdownMenuItem("PHP", href="/phpdata", active="exact"),
                                dbc.DropdownMenuItem("NodeJs", href="/nodejs",active="exact"),
                                dbc.DropdownMenuItem("Semgrep", href="/semgrep",active="exact"),
                                dbc.DropdownMenuItem("Zap Data", href="/zapdata", active="exact"),
                        ]),
                dbc.DropdownMenu(
                        label="Live Trends",
                        nav=True,
                        children=[
                                dbc.DropdownMenuItem("SAST", href="/sast", active="exact"),
                                dbc.DropdownMenuItem("DAST", href="/dast", active="exact"),
                                dbc.DropdownMenuItem("SCA", href="/sca", active="exact"),
                                dbc.DropdownMenuItem("SS", href="/ss",active="exact"),
                        ]),
                dbc.NavItem(dbc.NavLink("User", href="/user", active="exact")),
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
    if pathname == "/dashboard":
        # ToKen Count
        # select count(1) from boman_dev.sast_results;(SQL)
        sast_count = sast_result.scan_token.count()   
        dast_count = dast_result.scan_token.count()
        sc_count = secret_scanner_results.scan_token.count()
        sca_count = sca_result.scan_token.count()

        # Overall Scan Tools
        total_scan = {'Security Scanning Tools Names':['SAST','DAST','Secret Scan','SCA'],
                'Count of Each Scan':[sast_count,dast_count,sc_count,sca_count]}
        total_scan_count = sum(total_scan['Count of Each Scan'])

        # SAST tools Count
        sast_di = sast_result.tool_name.value_counts()
        sast_tool_name_count = {'Tool Name':sast_di.keys(),
                                'Tool Count':sast_di.values}

        # DAST tools Count
        dast_tools_names = dast_result.tool_name.value_counts()
        dast_tool_name_count = {'Tool Name':dast_tools_names.keys(),
                                'Tool Count':dast_tools_names.values}

        # SCA tools 
        sca_tools_names = sca_result.tool_name.value_counts()
        sca_tool_name_count = {'Tool Name':sca_tools_names.keys(),
                                'Tool Count':sca_tools_names.values}

        # SC Tools
        sc_tool_names = secret_scanner_results.tool_name.value_counts()
        sc_tool_names_count = {'Tool Name':sc_tool_names.keys(),
                                'Tool Count':sc_tool_names.values}
        
        # Total Sast Vulnerabilities Names
        sast_vuln_name = sast_result.vuln_name.value_counts()
        sast_vuln_name_count ={'Vulnerabilities Names':sast_vuln_name.keys()[0:10],
                        "Count Each Vulnerabilities":sast_vuln_name.values[0:10]
                        }
        # Total dast Vulnerabilities Names
        dast_vuln_name = dast_result.vuln_name.value_counts()
        dast_vuln_name_count ={'Vulnerabilities Names':dast_vuln_name.keys()[0:10],
                        "Count Each Vulnerabilities":dast_vuln_name.values[0:10]
                        }
        # Total SCA Vulnerabilities Names
        sca_vuln_name = sca_result.vuln_name.value_counts()
        sca_vuln_name_count ={'Vulnerabilities Names':sca_vuln_name.keys()[0:10],
                        "Count Each Vulnerabilities":sca_vuln_name.values[0:10]
                        }
        # Total SS Vulnerabilities Names
        ss_vuln_name = secret_scanner_results.vuln_name.value_counts()
        ss_vuln_name_count ={'Vulnerabilities Names':ss_vuln_name.keys()[0:10],
                        "Count Each Vulnerabilities":ss_vuln_name.values[0:10]
                        }

        # Machine Learning Model Preicated False Positive
        sast_tool_fp = sast_result.false_positive.value_counts()
        dast_tool_fp = dast_result.false_positive.value_counts()
        sast_fp_0=sast_tool_fp[0.0]
        dast_fp_0 = dast_tool_fp[0.0]
        total_false_postive = {'Total No of False Postive deteted by AI/ML':["False Postive",'True Postive'],
                "Count False Postive":[sast_tool_fp[1.0], dast_fp_0+sast_fp_0]
                }
        # Overall Repeated Vulnerabilities across applications
        df_overall= vuln[['tool_type','tool_name','boman_severity','vuln_name']]
        #df_overall.dropna(inplace=True)
        


        tool_master_data=[      html.H1('Boman.ai Analysis Dashboard',style={'textAlign':'center'}),
                                # Over all Scan Tools
                                
                                html.P("Overall Application and User Security Tools: "),
                                html.Li("This are the Top Used Security Scaners by the Customers"),
                                html.Li('Total Number of Scan Done across all the Security Scanning Tools: {}'.format(total_scan_count)),
                                #html.Hr,html.Br,
                                html.Li("Total Scan done in SAST is :...............  {}".format(sast_count)),
                                html.Li("Total Scan done in DAST is :...............  {}".format(dast_count)),
                                html.Li("Total Scan done in SCA is :................  {}".format(sca_count)),
                                html.Li("Total Scan Done in Secret Scan is :......  {}".format(sc_count)),
                                html.Br(),
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
                                        figure= px.bar(sast_tool_name_count, y='Tool Name',x='Tool Count',
                                                text_auto='.2s',
                                                color_discrete_sequence = px.colors.sequential.Aggrnyl,
                                                title='All SAST Scan Tool',labels={'x':"Tools Names ",'y':'Count of Each Scan Tools'}),
                                        config= {'displaylogo': False}
                                ),
                                # DAST Scan Tools
                                html.Li("Scan Tools Name is  :- {}:- Count:- {}".format(dast_tool_name_count['Tool Name'][0],dast_tool_name_count['Tool Count'][0])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][1],dast_tool_name_count['Tool Count'][1])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][2],dast_tool_name_count['Tool Count'][2])),
                                #html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][3],dast_tool_name_count['Tool Count'][3])),
                                dcc.Graph(id ='Tool_name_barchart',
                                        figure= px.pie(dast_tool_name_count, names='Tool Name',values='Tool Count',
                                                #text_auto='.2s',
                                                hole=.3,
                                                title='All DAST Scan Type',
                                                color_discrete_sequence = px.colors.sequential.Plasma,
                                                labels={'x':"Tools Names Type ",'y':'Count of Each Scan Tools'}
                                                ),
                                        config= {'displaylogo': False}
                                ),
                                # SCA Scan Tools 
                                html.Li("Scan Tools Name is  :- {}:- Count:- {}".format(sca_tool_name_count['Tool Name'][0],sca_tool_name_count['Tool Count'][0])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][1],dast_tool_name_count['Tool Count'][1])),
                                html.Li("Scan Tool Name is :- {}  Count:- {}".format(dast_tool_name_count['Tool Name'][2],dast_tool_name_count['Tool Count'][2])),
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
                                                title='Total Vulnerabilities in SAST DAST Predicate by Machine Learning Model'),
                                ),
                                # Total Repeated Vulnerabilities across All the applications
                                dcc.Graph(id='Total Repeated Vulnerabilities across All the applications',
                                        figure= px.bar(Repeated_Vulnerabilities_across_applications(), 
                                                        y='Vulnerabilities Names',
                                                        x='Count',
                                                        text_auto='.2s',
                                                        #hole=.1,
                                                        orientation='h',
                                                        color_discrete_sequence=px.colors.sequential.Sunsetdark,
                                                        title='Top Occurances of Vulnerabilities across All the applications'),
                                        config= {'displaylogo': False},
                                        ),
                                # Over all Repeated Tool with Vulnerabilities Names with Severity
                                dcc.Graph(id='Overall_Repeated_Vulnerabilities_Severity',                                        
                                figure= px.parallel_categories(df_overall.head(150), 
                                                        title = 'Total Repeated Vulnerabilities Names with Severity Level',
                                                        labels = {'tool_type':'Tool Type','tool_name':'Tool Names','boman_severity':'Severity','vuln_name':'Vulnerability Names'},
                                                        color_continuous_scale = px.colors.diverging.balance,
                                                        ),
                                        config= {'displaylogo': False},
                                        ),
                                # SAST 
                                dcc.Graph(id='Sast_vuln_names',
                                        figure= px.pie(sast_vuln_name_count, names='Vulnerabilities Names',
                                                                        values='Count Each Vulnerabilities',
                                                        #text_auto='.2s',
                                                        hole=.1,
                                                        color_discrete_sequence=px.colors.sequential.matter,
                                                        title='Top 10 Vulnerabilities in SAST',
                                                        labels={'x':"Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                  ),
                                # Total Repeated Vulnerabilities Severity in SAST across All the applications
                                dcc.Graph(id='Total Vulnerabilities Severity in SAST Tool across All the applications',
                                        figure= px.bar(vulnerabilities_severity(sast_result), 
                                                        x = 'Vulnerabilities Severity',
                                                        y = 'Vulnerabilities Count',
                                                        text_auto='.2s',
                                                        #hole=.1,
                                                        color_discrete_sequence=px.colors.sequential.Tealgrn,
                                                        title='Total Vulnerabilities Severity in SAST across All the applications'),
                                        config= {'displaylogo': False},
                                        ),
                                dcc.Graph(id='dast_vuln_names',
                                        figure= px.pie(dast_vuln_name_count, 
                                                        names='Vulnerabilities Names',
                                                        values='Count Each Vulnerabilities',
                                                        #text_auto='.2s',
                                                        #orientation='h',
                                                        hole=.2,
                                                        color_discrete_sequence=px.colors.sequential.RdBu,
                                                        title='Top 10 Vulnerabilities in DAST'),
                                                        #labels={'x':"Total Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                ),
                                # Total Repeated Vulnerabilities Severity in DAST across All the applications
                                dcc.Graph(id='Total Repeated Vulnerabilities Severity in DAST Tool across All the applications',
                                        figure= px.bar(vulnerabilities_severity(dast_result), 
                                                        x = 'Vulnerabilities Severity',
                                                        y = 'Vulnerabilities Count',
                                                        text_auto='.2s',
                                                        #hole=.1,
                                                        color_discrete_sequence=px.colors.sequential.Plasma,
                                                        title='Total Vulnerabilities Severity in DAST across All the applications'),
                                        config= {'displaylogo': False},
                                        ),
                                dcc.Graph(id='sca_vuln_names',
                                        figure= px.pie(sca_vuln_name_count, names='Vulnerabilities Names',values='Count Each Vulnerabilities',
                                                        #text_auto='.2s',
                                                        hole=.3,
                                                        color_discrete_sequence=px.colors.sequential.Rainbow,
                                                        title='Top 10 Vulnerabilities in SCA',
                                                        labels={'x':"Vulnerabilities Names",'y':'Count Each Vulnerabilities'}),
                                        config= {'displaylogo': False},
                                ),
                                # Total Repeated Vulnerabilities Severity in SCA across All the applications
                                dcc.Graph(id='Total Repeated Vulnerabilities Severity in SCA Tool across All the applications',
                                        figure= px.bar(vulnerabilities_severity(sca_result), 
                                                        x='Vulnerabilities Severity',
                                                        y='Vulnerabilities Count',
                                                        text_auto='.2s',
                                                        #hole=.1,
                                                        color_discrete_sequence=px.colors.cyclical.Phase,
                                                        title='Total Vulnerabilities Severity in SCA across All the applications'),
                                        config= {'displaylogo': False},
                                        ),
                                # Peak HR
                                dcc.Graph(id='peak',
                                        figure= top_three_peak(),
                                        config= {'displaylogo': False},
                                        ),
                                
                                
                                
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
                html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(brakeman_vuln_severity_count['Vulnerabilities Severity'][0],brakeman_vuln_severity_count['Vulnerabilities Count'][0])),
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
                html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(php_vuln_severity_count['Vulnerabilities Severity'][0],php_vuln_severity_count['Vulnerabilities Count'][0])),
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(php_vuln_severity_count['Vulnerabilities Severity'][1],php_vuln_severity_count['Vulnerabilities Count'][1])),
                #html.Li("Vulnerabilities Severity:- {}  Count:- {}".format(php_vuln_severity_count['Vulnerabilities Severity'][2],php_vuln_severity_count['Vulnerabilities Count'][2])),
                
                dcc.Graph(id='vuln_severity_graph',
                         figure=px.pie(php_vuln_severity_count, 
                                        names='Vulnerabilities Severity',
                                        values= 'Vulnerabilities Count',
                                        hole=.3,
                                        opacity = .3,
                                        #hover_data="label+percent+name",
                                        title='Vulnerabilities Severity In PHP Scan Tool'),config= {'displaylogo': False}
                         ),

                # PHP Vulnerabilities Confidence
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(php_vuln_confidence_count['Vulnerabilities Confidence'][0],php_vuln_confidence_count['Vulnerabilities Count'][0])),
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(php_vuln_confidence_count['Vulnerabilities Confidence'][1],php_vuln_confidence_count['Vulnerabilities Count'][1])),
                #html.Li("Vulnerabilities Confidence:- {}  Count:- {}".format(php_vuln_confidence_count['Vulnerabilities Confidence'][2],php_vuln_confidence_count['Vulnerabilities Count'][2])),
                dcc.Graph(id = "vuln_severity_barchart",
                         figure=px.bar(php_vuln_confidence_count, 
                                        x='Vulnerabilities Confidence',
                                        y = 'Vulnerabilities Count',
                                        color_discrete_sequence= px.colors.sequential.OrRd,
                                        title='Vulnerabilities Severity In PHP'),config= {'displaylogo': False}
                        ),
                # Total No False Positive and Nagative
                html.H4("Total No Result Processed by PHP Machine Learning Model API is:- {}".format(sum(php_false_postive_count['False Positive Count']))),
                #html.Li("True Positive is : {} :-  Count:- {}".format(php_false_postive_count['False Positive'][0],php_false_postive_count['False Positive Count'][0])),
                #html.Li("False Postive is : {} :-   Count:- {}".format(php_false_postive_count['False Positive'][1],php_false_postive_count['False Positive Count'][1])),
                dcc.Graph(id = "false_positive_barchart",
                         figure=px.pie(php_false_postive_count, 
                                names = 'False Positive',
                                hole = .5,
                                color_discrete_sequence = px.colors.sequential.Darkmint,
                                values = 'False Positive Count', 
                                title='False Positive'),config= {'displaylogo': False}
                        ),
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
        # False Postive Data 
        nodejs_false_postive = df_njsscan['false_positive'].value_counts()
        nodejs_false_postive_count = {'False Positive':nodejs_false_postive.keys(),
                        'False Positive Count': nodejs_false_postive.values
                        }
        nodejs_high_count = df_njsscan.vuln_confidence.str.lower().value_counts()
        
        nodejs = [        
                html.H1("Nodejs live data visualizationsis"),
                html.Li("Total No of Scan Done So far: {}".format(nodejs_no_of_scan)),

                # Vulnerabilities Names and it Count
                #html.Li("Vulnerabilities Name:- {}  Vulnerabilities Count:- {}".format(nodejs_vuln_name_count['Vulnerabilities Name'][0],nodejs_vuln_name_count['Tool Count'][0])),
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
        return [html.H1('SemGrep Dashboard Comming Soon')]
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

        risk_code = df_zap.boman_severity.value_counts()
        risk_code_count = {'Severity':risk_code.keys(),
                        "Severity Count":risk_code.values}
        confidence = df_zap.confidence.value_counts()
        confidence_code = {'Confidence':confidence.keys(),
                        'Count':confidence.values}
        risk_desc  = df_zap.risk_desc.value_counts()
        risk_desc_count = {'Risk desc':risk_desc.keys(),'Count':risk_desc.values}

        cwe = df_zap.cwe.value_counts()
        cwe_count = {'CWE No':cwe.keys(),"CWE Count":cwe.values}

        fasle_postive = df_zap.false_positive.value_counts()
        fasle_postive_count = {'fasle_postive':fasle_postive.keys(),
                                'Count':fasle_postive.values
                                }

        zap = [ html.H2('Zap Live Dashboard:'),
                html.Li("Total No of Scan Done so far: {} ".format(zap_no_of_scan)),
                html.H4('Different Scan Done With Different Tool Names'),
                html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][0],zap_tool_names_count['Count'][0])),
                html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][1],zap_tool_names_count['Count'][1])),
                html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][2],zap_tool_names_count['Count'][2])),
                #html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][3],zap_tool_names_count['Count'][3])),
                #html.Li("Tool names {} and it's Count {}".format(zap_tool_names_count['Tool Names'][4],zap_tool_names_count['Count'][4])),
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
                html.H5('Total Severity Level in Zap tools {}'.format(sum(risk_code.values))),
                dcc.Graph(id='risk_bar',
                        figure= px.bar(risk_code_count,
                                        x = 'Severity',
                                        y = 'Severity Count',
                                        title='Top Severity level in ZAP Tool',
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
                                title='CWE in ZAP Tool',
                                hole=.4,
                                color_discrete_sequence= px.colors.sequential.Plasma),
                        config= {'displaylogo': False}
                        ),
                html.H5('Total Confidence Count in Zap tools {}'.format(sum(confidence.values))),
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
                # Machine Learning model False postive Removel
                html.H4("Total No Result Processed by ZAP Machine Learning Model API is:- {}".format(sum(fasle_postive_count['Count']))),
                html.Li("True Positive is : {} :-  Count:- {}".format(fasle_postive_count['fasle_postive'][0],fasle_postive_count['Count'][0])),
                html.Li("False Postive is : {} :-   Count:- {}".format(fasle_postive_count['fasle_postive'][1],fasle_postive_count['Count'][1])),
                dcc.Graph(id = "false_positive_barchart",
                         figure=px.pie(fasle_postive_count, 
                                names = 'fasle_postive',
                                hole = .5,
                                color_discrete_sequence = px.colors.sequential.Darkmint,
                                values = 'Count', 
                                title='False Positive'),config= {'displaylogo': False}
                        ),
                
        ] 
        return zap
    elif pathname == "/user":

        return True
    elif pathname == "/sast":

        # Year Wise
        by_year = pd.to_datetime(sast_result['created_at']).dt.strftime('%Y').value_counts().sort_index()
        #by_year.index = pd.PeriodIndex(by_year.index)
        by_year = by_year.rename_axis('Yearly').reset_index(name='counts')
        
        # quarter Wise
        by_quarter = pd.to_datetime(sast_result['created_at']).dt.to_period('Q').value_counts().sort_index()
        by_quarter.index = pd.PeriodIndex(by_quarter.index)
        by_quarter = by_quarter.rename_axis('quarter').reset_index(name='counts')

        # Month Wise
        by_month = pd.to_datetime(sast_result['created_at']).dt.strftime('%m').value_counts().sort_index()
        by_month = by_month.rename_axis('month').reset_index(name='counts')

        # Weekly wise
        by_weak = pd.to_datetime(sast_result['created_at']).dt.strftime('%A').value_counts().sort_index()
        #by_weak.index = pd.PeriodIndex(by_weak.index)
        by_weak = by_weak.rename_axis('weekly').reset_index(name='counts')

        # Day wise
        by_day = pd.to_datetime(sast_result['created_at']).dt.strftime('%d').value_counts().sort_index()
        #by_day.index = pd.PeriodIndex(by_day.index)
        by_day = by_day.rename_axis('Days').reset_index(name='counts')
        
        sast_df = sast_result[['tool_type','tool_name','boman_severity','vuln_name']].head(100)

        trands_plot = [ 
                html.H2('Live Static Application Security Testing (SAST)  Trend Analysis',style={'textAlign':'center'}),
                html.Hr(),
                #html.H4("SAST Yearly  Issues Creations Trends"),
                # dcc.Graph(id = "yearly_count",
                #          figure=px.line(x=by_year['Yearly'].astype(dtype=str),
                #                                                 y=by_year['counts'],
                #                                                 labels={'x':'Yearly', 'y':'Vulnerabilities Count'},
                #                                                 markers=True,
                #                                                 title='SAST Yearly  Issues Creations Trends',
                #                                                 color_discrete_sequence=px.colors.cyclical.HSV),

                #          config= {'displaylogo': False},
                #         ),
                #html.H4("SAST Quarterly Issues Created"),
                dcc.Graph(id='quarter_count',
                        config= {'displaylogo': False},
                        figure= px.line(x=by_quarter['quarter'].astype(dtype=str), 
                                y=by_quarter['counts'],
                                markers= True,
                                title = 'SAST Quarterly Issues Created',
                                labels = {'x':'Quarterly Issues','y':'Vulnerabilities Count'},
                                color_discrete_sequence=px.colors.sequential.Cividis)
                        ),
                #html.H4("SAST Monthly Issues Created"),
                dcc.Graph(id='month_count',
                        config= {'displaylogo': False},
                        figure= px.line(x=by_month['month'].astype(dtype=str), 
                                y=by_month['counts'],
                                markers= True,
                                title = 'SAST Monthly Issues Created',
                                labels = {'x':'Monthly Issues','y':'Vulnerabilities Count'},
                                color_discrete_sequence=px.colors.sequential.Magenta)
                        ),
                #html.H4("SAST Weekly Issues Created"),
                dcc.Graph(id='weekly_count',
                        config= {'displaylogo': False},
                        figure= px.line(x=by_weak['weekly'].astype(dtype=str), 
                                y=by_weak['counts'],
                                markers= True,
                                title = 'SAST Weekly Issues Created',
                                labels = {'x':'Weekly Issues','y':'Vulnerabilities Count'},
                                color_discrete_sequence=px.colors.sequential.Electric),
                        ),
                #html.H4("SAST Daily Issues Created"),
                dcc.Graph(id='daily_count',
                        config= {'displaylogo': False},
                        figure= px.line(by_day,
                                        x='Days',
                                        y='counts',
                                        title = "SAST Daily Issues Created",
                                        labels = {'Days':'Daily Issues','counts':'Vulnerabilities Count'},
                                        color_discrete_sequence= px.colors.sequential.Bluered)),
                # SAST Repeated Vulnerabilities across applications with Severity
                  dcc.Graph(id='correlation_flow',
                        config={'displaylogo':False},
                        figure= px.parallel_categories(sast_df,
                                        title = "SAST Correlation Flow Tool with Severity and Vulnerabilities Name",
                                        color_continuous_scale=px.colors.sequential.Greens,
                                         labels={'tool_name':'Tool Names', 'boman_severity':'Severity','vuln_name':'Vulnerabilities Names'},
        )),
                ]
        return trands_plot
    elif pathname == "/dast":
        # Year Wise
        by_year = pd.to_datetime(dast_result['created_at']).dt.strftime('%Y').value_counts().sort_index()
        #by_year.index = pd.PeriodIndex(by_year.index)
        by_year = by_year.rename_axis('Yearly').reset_index(name='counts')

        # quarter Wise
        by_quarter = pd.to_datetime(dast_result['created_at']).dt.to_period('Q').value_counts().sort_index()
        by_quarter.index = pd.PeriodIndex(by_quarter.index)
        by_quarter = by_quarter.rename_axis('quarter').reset_index(name='counts')

        # Month Wise
        by_month = pd.to_datetime(dast_result['created_at']).dt.strftime('%m').value_counts().sort_index()
        by_month = by_month.rename_axis('month').reset_index(name='counts')

        # Weekly wise
        by_weak = pd.to_datetime(dast_result['created_at']).dt.strftime('%A').value_counts().sort_index()
        #by_weak.index = pd.PeriodIndex(by_weak.index)
        by_weak = by_weak.rename_axis('weekly').reset_index(name='counts')

        # Day wise
        by_day = pd.to_datetime(dast_result['created_at']).dt.strftime('%d').value_counts().sort_index()
        #by_day.index = pd.PeriodIndex(by_day.index)
        by_day = by_day.rename_axis('Days').reset_index(name='counts')

        dast_df = dast_result[['tool_type','tool_name','boman_severity','vuln_name']]

        trands_plot = [ 
        html.H2('Live Dynamic Application Security Testing (DAST)  Trend Analysis',style={'textAlign':'center'}),
        html.Hr(),
        
        # dcc.Graph(id = "yearly_count",
        #         figure=px.line(x=by_year['Yearly'].astype(dtype=str),
        #                                         y=by_year['counts'],
        #                                         labels={'x':'Yearly', 'y':'Vulnerabilities Count'},
        #                                         markers=True,
        #                                         title='DAST Yearly  Issues Creations Trends',
        #                                         color_discrete_sequence=px.colors.cyclical.HSV),

        #         config= {'displaylogo': False},
        # ),
     
        dcc.Graph(id='quarter_count',
        config= {'displaylogo': False},
        figure= px.line(x=by_quarter['quarter'].astype(dtype=str), 
                y=by_quarter['counts'],
                markers= True,
                title = 'DAST Quarterly Issues Created',
                labels = {'x':'Quarterly Issues','y':'Vulnerabilities Count'},
                color_discrete_sequence=px.colors.sequential.Cividis)
        ),
        
        dcc.Graph(id='month_count',
        config= {'displaylogo': False},
        figure= px.line(x=by_month['month'].astype(dtype=str), 
                y=by_month['counts'],
                markers= True,
                title = 'DAST Monthly Issues Created',
                labels = {'x':'Monthly Issues','y':'Vulnerabilities Count'},
                color_discrete_sequence=px.colors.sequential.Magenta)
        ),
        
        dcc.Graph(id='weekly_count',
        config= {'displaylogo': False},
        figure= px.line(x=by_weak['weekly'].astype(dtype=str), 
                y=by_weak['counts'],
                markers= True,
                title = 'DAST Weekly Issues Created',
                labels = {'x':'Weekly Issues','y':'Vulnerabilities Count'},
                color_discrete_sequence=px.colors.sequential.Electric),
        ),
        
        dcc.Graph(id='daily_count',
        config= {'displaylogo': False},
        figure= px.line(by_day,
                        x='Days',
                        y='counts',
                        title = "DAST Daily Issues Created",
                        labels = {'Days':'Daily Issues','counts':'Vulnerabilities Count'},
                        color_discrete_sequence= px.colors.sequential.Bluered)),
        dcc.Graph(id='correlation_flow',
        config={'displaylogo':False},
        figure= px.parallel_categories(dast_df,
                                        title = "DAST Correlation Flow Tool with Severity and Vulnerabilities Name",
                                        color_continuous_scale=px.colors.sequential.Inferno,
                                         labels={'tool_name':'Tool Names', 'boman_severity':'Severity','vuln_name':'Vulnerabilities Names'},
        )),
        ]
        return trands_plot
    elif pathname == "/sca":
        # Year Wise
        by_year = pd.to_datetime(sca_result['created_at']).dt.strftime('%Y').value_counts().sort_index()
        #by_year.index = pd.PeriodIndex(by_year.index)
        by_year = by_year.rename_axis('Yearly').reset_index(name='counts')

        # quarter Wise
        by_quarter = pd.to_datetime(sca_result['created_at']).dt.to_period('Q').value_counts().sort_index()
        by_quarter.index = pd.PeriodIndex(by_quarter.index)
        by_quarter = by_quarter.rename_axis('quarter').reset_index(name='counts')

        # Month Wise
        by_month = pd.to_datetime(sca_result['created_at']).dt.strftime('%m').value_counts().sort_index()
        by_month = by_month.rename_axis('month').reset_index(name='counts')

        # Weekly wise
        by_weak = pd.to_datetime(sca_result['created_at']).dt.strftime('%A').value_counts().sort_index()
        #by_weak.index = pd.PeriodIndex(by_weak.index)
        by_weak = by_weak.rename_axis('weekly').reset_index(name='counts')

        # Day wise
        by_day = pd.to_datetime(sca_result['created_at']).dt.strftime('%d').value_counts().sort_index()
        #by_day.index = pd.PeriodIndex(by_day.index)
        by_day = by_day.rename_axis('Days').reset_index(name='counts')

        sca_df = sca_result[['tool_type','tool_name','boman_severity','vuln_name']]

        trands_plot = [ 
        html.H2('Live Software Composition Analysis (SCA)  Trend Analysis',style={'textAlign':'center'}),
        html.Hr(),
        
        # dcc.Graph(id = "yearly_count",
        #         figure=px.line(x=by_year['Yearly'].astype(dtype=str),
        #                                         y=by_year['counts'],
        #                                         labels={'x':'Yearly', 'y':'Vulnerabilities Count'},
        #                                         markers=True,
        #                                         title='SCA Yearly  Issues Creations Trends',
        #                                         color_discrete_sequence=px.colors.cyclical.HSV),

        #         config= {'displaylogo': False},
        # ),
        dcc.Graph(id='quarter_count',
        config= {'displaylogo': False},
        figure= px.line(x=by_quarter['quarter'].astype(dtype=str), 
                y=by_quarter['counts'],
                markers= True,
                title = 'SCA Quarterly Issues Created',
                labels = {'x':'Quarterly Issues','y':'Vulnerabilities Count'},
                color_discrete_sequence=px.colors.sequential.Cividis)
        ),
        
        dcc.Graph(id='month_count',
        config= {'displaylogo': False},
        figure= px.line(x=by_month['month'].astype(dtype=str), 
                y=by_month['counts'],
                markers= True,
                title = 'SCA Monthly Issues Created',
                labels = {'x':'Monthly Issues','y':'Vulnerabilities Count'},
                color_discrete_sequence=px.colors.sequential.Magenta)
        ),
        
        dcc.Graph(id='weekly_count',
        config= {'displaylogo': False},
        figure= px.line(x=by_weak['weekly'].astype(dtype=str), 
                y=by_weak['counts'],
                markers= True,
                title = 'SCA Weekly Issues Created',
                labels = {'x':'Weekly Issues','y':'Vulnerabilities Count'},
                color_discrete_sequence=px.colors.sequential.Electric),
        ),
        dcc.Graph(id='daily_count',
        config= {'displaylogo': False},
        figure= px.line(by_day,
                        x='Days',
                        y='counts',
                        title = "SCA Daily Issues Created",
                        labels = {'Days':'Daily Issues','counts':'Vulnerabilities Count'},
                        color_discrete_sequence= px.colors.sequential.Bluered)),
        dcc.Graph(id='correlation_flow',
        config={'displaylogo':False},
        figure= px.parallel_categories(sca_df,
                                        title = "SCA Correlation Flow Tool with Severity and Vulnerabilities Name",
                                        color_continuous_scale=px.colors.sequential.Inferno,
                                         labels={'tool_name':'Tool Names', 'boman_severity':'Severity','vuln_name':'Vulnerabilities Names'},
        )),
        ]
        return trands_plot
    elif pathname == "/ss":
        # Year Wise
        by_year = pd.to_datetime(secret_scanner_results['created_at']).dt.strftime('%Y').value_counts().sort_index()
        #by_year.index = pd.PeriodIndex(by_year.index)
        by_year = by_year.rename_axis('Yearly').reset_index(name='counts')

        # quarter Wise
        by_quarter = pd.to_datetime(secret_scanner_results['created_at']).dt.to_period('Q').value_counts().sort_index()
        by_quarter.index = pd.PeriodIndex(by_quarter.index)
        by_quarter = by_quarter.rename_axis('quarter').reset_index(name='counts')

        # Month Wise
        by_month = pd.to_datetime(secret_scanner_results['created_at']).dt.strftime('%m').value_counts().sort_index()
        by_month = by_month.rename_axis('month').reset_index(name='counts')

        # Weekly wise
        by_weak = pd.to_datetime(secret_scanner_results['created_at']).dt.strftime('%A').value_counts().sort_index()
        #by_weak.index = pd.PeriodIndex(by_weak.index)
        by_weak = by_weak.rename_axis('weekly').reset_index(name='counts')

        # Day wise
        by_day = pd.to_datetime(secret_scanner_results['created_at']).dt.strftime('%d').value_counts().sort_index()
        #by_day.index = pd.PeriodIndex(by_day.index)
        by_day = by_day.rename_axis('Days').reset_index(name='counts')

        df = secret_scanner_results[['tool_name','boman_severity','vuln_name']]

        trands_plot = [ 
        html.H2('Live Secret Scanner (SS)  Trend Analysis',style={'textAlign':'center'}),
        html.Hr(),
        
        #dcc.Graph(id = "yearly_count",
        #        figure=px.line(x=by_year['Yearly'].astype(dtype=str),
        #                                        y=by_year['counts'],
        #                                        labels={'x':'Yearly', 'y':'Vulnerabilities Count'},
        #                                        markers=True,
        #                                        title='Secret Scanner Yearly  Issues Creations Trends',
        #                                        color_discrete_sequence=px.colors.cyclical.HSV),

        #        config= {'displaylogo': False},
        #),
     
        dcc.Graph(id='quarter_count',
        config= {'displaylogo': False},
        figure= px.line(x=by_quarter['quarter'].astype(dtype=str), 
                y=by_quarter['counts'],
                markers= True,
                title = 'Secret Scanner Quarterly Issues Created',
                labels = {'x':'Quarterly Issues','y':'Vulnerabilities Count'},
                color_discrete_sequence=px.colors.sequential.Cividis)
        ),
        
        dcc.Graph(id='month_count',
        config= {'displaylogo': False},
        figure= px.line(x=by_month['month'].astype(dtype=str), 
                y=by_month['counts'], # Change to NO of Vuln
                markers= True,
                title = 'Secret Scanner Monthly Issues Created',
                labels = {'x':'Monthly Issues','y':'Vulnerabilities Count'},
                color_discrete_sequence=px.colors.sequential.Magenta)
        ),
        
        dcc.Graph(id='weekly_count',
        config= {'displaylogo': False},
        figure= px.line(x=by_weak['weekly'].astype(dtype=str), 
                y=by_weak['counts'],
                markers= True,
                title = 'Secret Scanner Weekly Issues Created',
                labels = {'x':'Weekly Issues','y':'Vulnerabilities Count'},
                color_discrete_sequence=px.colors.sequential.Electric),
        ),
        
        dcc.Graph(id='daily_count',
        config= {'displaylogo': False},
        figure= px.line(by_day,
                        x='Days',
                        y='counts',
                        title = "Secret Scanner Daily Issues Created",
                        labels = {'Days':'Daily Issues','counts':'Vulnerabilities Count'},
                        color_discrete_sequence= px.colors.sequential.Bluered)),
        
        dcc.Graph(id='correlation_flow',
        config={'displaylogo':False},
        figure= px.parallel_categories(df,
                                        title = "Secret Scanner Correlation Flow Tool with Severity and Vulnerabilities Name",
                                        color_continuous_scale=px.colors.sequential.Inferno,
                                         labels={'tool_name':'Tool Names', 'boman_severity':'Severity','vuln_name':'Vulnerabilities Names'},
        )),
        ]
        
        return trands_plot
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